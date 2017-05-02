# Detecting RedLeaves for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv redleavesscan.py volatility/plugins/malware
# 3. python vol.py [ redleavesscan | redleavesconfig ] -f images.mem --profile=Win7SP1x64

import volatility.plugins.taskmods as taskmods
import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.debug as debug
import volatility.plugins.malware.malfind as malfind
import volatility.plugins.malware as malware
import re
from struct import pack, unpack, unpack_from, calcsize

try:
    import yara
    has_yara = True
except ImportError:
    has_yara = False

redleaves_sig = {
    'namespace1' : 'rule RedLeaves { \
                    strings: \
                       $v1 = "red_autumnal_leaves_dllmain.dll" \
                       $b1 = { FF FF 90 00 } \
                    condition: $v1 and $b1 at 0}'
}

CONF_PATTERNS = [["RedLeaves", re.compile("\x68\x88\x13\x00\x00\xFF", re.DOTALL)]
                 ]

CONNECT_MODE = {1 : 'TCP' , 2 : 'HTTP', 3 : 'HTTPS', 4 : 'TCP and HTTP'}


class patternCheck():
    def __init__(self, malname, data):
        for c_name, c_pt in CONF_PATTERNS:
            if str(malname) in c_name:
                if re.search(c_pt, data):
                    self.m_conf = re.search(c_pt, data)
                    break
            else:
                self.m_conf = None

class vad_ck():
    def get_vad_end(self, task, address):
        for vad in task.VadRoot.traverse():
            if address == vad.Start:
                return vad.End+1

        return None

class redleavesScan(taskmods.DllList):
    "Detect processes infected with redleaves malware"

    @staticmethod
    def is_valid_profile(profile):
        return (profile.metadata.get('os', 'unknown') == 'windows'), profile.metadata.get('memory_model', '32bit')

    def get_vad_base(self, task, address):
        for vad in task.VadRoot.traverse():
            if address >= vad.Start and address < vad.End:
                return vad.Start

        return None

    def calculate(self):

        if not has_yara:
            debug.error("Yara must be installed for this plugin")

        addr_space = utils.load_as(self._config)

        os , memory_model = self.is_valid_profile(addr_space.profile)
        if not os:
            debug.error("This command does not support the selected profile.")

        rules = yara.compile(sources = redleaves_sig)

        for task in self.filter_tasks(tasks.pslist(addr_space)):
            scanner = malfind.VadYaraScanner(task = task, rules = rules)

            for hit, address in scanner.scan():

                vad_base_addr = self.get_vad_base(task, address)

                yield task, vad_base_addr, hit, memory_model
                break

    def render_text(self, outfd, data):

        self.table_header(outfd, [("Name", "20"),
                                  ("PID", "8"),
                                  ("Data VA", "[addrpad]"),
                                  ("Malware Name", "13")])

        for task, start, malname, memory_model in data:
            self.table_row(outfd, task.ImageFileName, task.UniqueProcessId, start, malname)


class redleavesConfig(redleavesScan):
    "Parse the RedLeaves configuration"

    def parse_config(self, cfg_blob, cfg_sz, cfg_addr, outfd):
        server1 = unpack_from('<64s', cfg_blob, 0x0)[0]
        server2 = unpack_from('<64s', cfg_blob, 0x40)[0]
        server3 = unpack_from('<64s', cfg_blob, 0x80)[0]
        port = unpack_from('<I', cfg_blob, 0xC0)[0]
        mode = unpack_from('<I', cfg_blob, 0x1D0)[0]
        id = unpack_from('<64s', cfg_blob, 0x1E4)[0]
        mutex = unpack_from('<550s', cfg_blob, 0x500)[0]
        injection = unpack_from('<104s', cfg_blob, 0x726)[0]
        rc4key = unpack_from('<10s', cfg_blob, 0x82A)[0]

        if "exe" not in injection.replace('\0',''):
            injection = list(injection)
            i = 0
            for s in injection:
                xor = ord(s) ^ ord(injection[-1])
                injection[i] = chr(xor)
                i += 1
            injection = "".join(injection)

        ## config write
        outfd.write("[RedLeaves Config Info]\n")
        outfd.write("Server1\t\t\t: %s\n" % server1.split('\0')[0])
        outfd.write("Server2\t\t\t: %s\n" % server2.split('\0')[0])
        outfd.write("Server3\t\t\t: %s\n" % server3.split('\0')[0])
        outfd.write("Port\t\t\t: %i\n" % port)
        outfd.write("Mode\t\t\t: %i (%s)\n" % (mode, CONNECT_MODE[mode]))
        outfd.write("ID\t\t\t: %s\n" % id.split('\0')[0])
        outfd.write("Mutex\t\t\t: %s\n" % mutex.replace('\0',''))
        outfd.write("Injection Process\t: %s\n" % injection.replace('\0',''))
        outfd.write("RC4 Key\t\t\t: %s\n" % rc4key.split('\0')[0])

    def render_text(self, outfd, data):

        delim = '-' * 70

        for task, start, malname, memory_model in data:
            if "RedLeaves" in str(malname):
                proc_addr_space = task.get_process_address_space()

                data = proc_addr_space.zread(start, vad_ck().get_vad_end(task, start)-start)

                loadp = patternCheck(malname ,data)
                if loadp.m_conf is None:
                    continue

                offset_conf = loadp.m_conf.start()
                config_size = 2100

                offset_conf -= 1
                while data[offset_conf]!="\xC7" and data[offset_conf]!="\xBE" and data[offset_conf]!="\xBF":
                    offset_conf -= 1

                if data[offset_conf]!="\xC7" and data[offset_conf]!="\xBE" and data[offset_conf]!="\xBF":
                    continue

                if data[offset_conf]=="\xC7" and data[offset_conf + 1]!="\x85" and data[offset_conf + 1]!="\x45":
                    offset_conf -= 6

                # get address
                if data[offset_conf]=="\xC7" and data[offset_conf + 1]!="\x85":
                    (config_addr, ) = unpack("=I", data[offset_conf+3:offset_conf+7])
                elif data[offset_conf]=="\xC7" and data[offset_conf + 1]=="\x85":
                    (config_addr, ) = unpack("=I", data[offset_conf+6:offset_conf+10])
                else:
                    (config_addr, ) = unpack("=I", data[offset_conf+1:offset_conf+5])

                if config_addr < start:
                    continue

                outfd.write("{0}\n".format(delim))
                outfd.write("RedLeaves Settings:\n\n")

                config_addr -= start
                config_data = data[config_addr:config_addr+config_size]
                outfd.write("Process: %s (%d)\n\n" % (task.ImageFileName, task.UniqueProcessId))

                if len(config_data) > 0:
                    self.parse_config(config_data, config_size, config_addr, outfd)
