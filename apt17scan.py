# Detecting APT17 malware for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv apt17scan.py volatility/plugins/malware
# 3. python vol.py [ apt17scan | derusubiconfig | hikitconfig | agtidconfig ] -f images.mem --profile=Win7SP1x64

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

apt17_sig = {
    'namespace1' : 'rule Derusbi { \
                    strings: \
                       $v1 = "_crt_debugger_hook" \
                       $v2 = "Extend command exited" wide\
                       $v3 = "Internal Cmd v" wide\
                    condition: $v1 and $v2 and $v3}',
    'namespace2' : 'rule Hikit { \
                    strings: \
                       $v1 = "matrix_password" wide\
                       $v2 = "Global\\\%s__SHOW__" wide\
                       $v3 = "Global\\\%s__HIDE__" wide\
                       $v4 = "Global\\\%s__STOP__" wide\
                    condition: $v1 and $v2 and $v3 and $v4}',
    'namespace3' : 'rule Blackcoffee { \
                    strings: \
                       $v1 = "Global\\\PnP_No_Management" \
                       $v2 = "HTTPMail Password2" wide\
                       $v3 = "Not Support This Function!" \
                       $b1 = { 01 10 06 80 75 }\
                    condition: $v1 and $b1 and ($v2 or $v3)}',
    'namespace4' : 'rule Agtid { \
                    strings: \
                       $v1 = "SessionID" \
                       $v2 = "Agtid" \
                       $v3 = "DGGYDSYRL" \
                       $v4 = "RC4VIMVIM!!@@##" \
                       $v5 = "Upload failed!" wide\
                       $v6 = "Can\'t open shell!" wide\
                       $v7 = "SessionID=abcde" \
                       $mz = { 4D 5A 90 00 } \
                       $b1 = { 00 E1 F5 05 77 }\
                       $b2 = { 40 42 0F 00 39 }\
                    condition: $mz at 0 and ($v1 and $v4) or ($v2 and $v3) or $v7 and $v5 and $v6 and $b1 and $b2}',
    'namespace5' : 'rule Preshin { \
                    strings: \
                       $v1 = "Ultro_ISO_0369" \
                       $v2 = "WinVer6.0" \
                       $v3 = "ah8d" \
                       $b1 = { 65 B4 CA 65 }\
                       $b2 = { 0F D3 65 7D }\
                    condition: $v1 and $v2 and $v3 and $b1 and $b2}',
    'namespace6' : 'rule McRat { \
                    strings: \
                       $v1 = "__rat_UnInstall__%d" wide\
                    condition: $v1}'
}

CONF_PATTERNS = [["Derusbi", re.compile("\x30\x75\x00\x00\xFF\x15", re.DOTALL)],
                 ["Agtid", re.compile("\x00\x00\x81\xEC\x3C\x06\x00\x00\x53", re.DOTALL)],
                 ["Hikit", re.compile("\x68(....)\xC7\x05(....)\x01\x00\x00\x00\xE8", re.DOTALL)]
                 ]

SIZE_PATTERNS = [["Derusbi", re.compile("\x81\xBD(....)\x00\xE9\x07\x00\x73", re.DOTALL)]
                 ]

DERUSBI_CONNECT_MODE1 = {0 : 'Unknown'   , 1 : 'Random Binary', 2 : 'Random Binary via Proxy', 3 : 'Unknown',
                         4 : 'HTTP POST' , 5 : 'Unknown'      , 6 : 'Unknown'}

DERUSBI_CONNECT_MODE2 = {0 : 'All Pattern'         , 1 : 'Random Binary', 2 : 'Random Binary via Proxy', 3 : 'HTTP POST',
                         4 : 'HTTP POST via Proxy' , 5 : 'Unknown'      , 6 : 'Unknown'}

class patternCheck():
    def __init__(self, malname, data):
        for c_name, c_pt in CONF_PATTERNS:
            if c_name in str(malname):
                self.m_conf = re.search(c_pt, data)
                break
            else:
                self.m_conf = None

        for s_name, s_pt in SIZE_PATTERNS:
            if s_name in str(malname):
                self.m_size = re.search(s_pt, data)
                break
            else:
                self.m_size = None

class vad_ck():
    def get_vad_end(self, task, address):
        for vad in task.VadRoot.traverse():
            if address == vad.Start:
                return vad.End+1

        return None

class apt17Scan(taskmods.DllList):
    "Detect processes infected with APT17 malware"

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

        rules = yara.compile(sources = apt17_sig)

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

        for task, start, malname in data:
            self.table_row(outfd, task.ImageFileName, task.UniqueProcessId, start, malname)

class derusbiConfig(apt17Scan):
    "Parse the Derusbi configuration"

    def parse_config(self, cfg_blob, cfg_sz, cfg_addr, outfd):
        if cfg_sz == 680:
            ID = unpack_from('<64s', cfg_blob, 0x0)[0]
            server = unpack_from('<256s', cfg_blob, 0xc0)[0]
            sleeptime = unpack_from('<I', cfg_blob, 0x1c0)[0]
            service = unpack_from('<32s', cfg_blob, 0x1c4)[0]
            mode = unpack_from('<I', cfg_blob, 0x1e4)[0]
            proxyname1 = unpack_from('<32s', cfg_blob, 0x1e8)[0]
            proxyuser1 = unpack_from('<16s', cfg_blob, 0x208)[0]
            proxypass1 = unpack_from('<16s', cfg_blob, 0x218)[0]
            proxyname2 = unpack_from('<32s', cfg_blob, 0x228)[0]
            proxyuser2 = unpack_from('<16s', cfg_blob, 0x248)[0]
            proxypass2 = unpack_from('<16s', cfg_blob, 0x258)[0]
            proxyname3 = unpack_from('<32s', cfg_blob, 0x268)[0]
            proxyuser3 = unpack_from('<16s', cfg_blob, 0x288)[0]
            proxypass3 = unpack_from('<16s', cfg_blob, 0x298)[0]
        elif cfg_sz == 692:
            ID = unpack_from('<64s', cfg_blob, 0x0)[0]
            server = unpack_from('<256s', cfg_blob, 0x40)[0]
            sleeptime = unpack_from('<I', cfg_blob, 0x140)[0]
            service = unpack_from('<32s', cfg_blob, 0x144)[0]
            mode = unpack_from('<I', cfg_blob, 0x164)[0]
            proxyname1 = unpack_from('<32s', cfg_blob, 0x168)[0]
            proxyuser1 = unpack_from('<16s', cfg_blob, 0x188)[0]
            proxypass1 = unpack_from('<16s', cfg_blob, 0x198)[0]
            installpath = unpack_from('<260s', cfg_blob, 0x1a8)[0]
            if unpack_from('<I', cfg_blob, 0x2ac)[0] == 0:
                autorun = 'Disable'
            else:
                autorun = 'Enable'
            if unpack_from('<I', cfg_blob, 0x2b0)[0] == 0:
                dumppe = 'Disable'
            else:
                dumppe = 'Enable'
        else:
            outfd.write("This config size is not supported.\n\n")
            return None

        ## config write
        outfd.write("[Derusbi Config Info]\n")
        outfd.write("ID\t\t: %s\n" % ID.split('-')[0])
        outfd.write("Server list\t: %s\n" % server.split('\0')[0])
        outfd.write("Sleep time\t: %i\n" % sleeptime)
        outfd.write("Service name\t: %s\n" % service.split('\0')[0])
        if cfg_sz == 680:
            outfd.write("Connect mode\t: %i (%s)\n" % (mode, DERUSBI_CONNECT_MODE1[mode]))
        elif cfg_sz == 692:
            outfd.write("Connect mode\t: %i (%s)\n" % (mode, DERUSBI_CONNECT_MODE2[mode]))
        outfd.write("Proxy setting 1\n")
        outfd.write("   Server\t: %s\n" % proxyname1.split('\0')[0])
        outfd.write("   User\t\t: %s\n" % proxyuser1.split('\0')[0])
        outfd.write("   Password\t: %s\n" % proxypass1.split('\0')[0])
        if cfg_sz == 680:
            outfd.write("Proxy setting 2\n")
            outfd.write("   Server\t: %s\n" % proxyname2.split('\0')[0])
            outfd.write("   User\t\t: %s\n" % proxyuser2.split('\0')[0])
            outfd.write("   Password\t: %s\n" % proxypass2.split('\0')[0])
            outfd.write("Proxy setting 3\n")
            outfd.write("   Server\t: %s\n" % proxyname3.split('\0')[0])
            outfd.write("   User\t\t: %s\n" % proxyuser3.split('\0')[0])
            outfd.write("   Password\t: %s\n" % proxypass3.split('\0')[0])
        elif cfg_sz == 692:
            outfd.write("Install Path\t: %s\n" % installpath.split('\0')[0])
            outfd.write("Create autorun\t: %s\n" % autorun)
            outfd.write("Dump PE file\t: %s\n" % dumppe)

    def render_text(self, outfd, data):

        delim = '-' * 70

        for task, start, malname, memory_model in data:
            proc_addr_space = task.get_process_address_space()

            data = proc_addr_space.zread(start, vad_ck().get_vad_end(task, start)-start)

            loadp = patternCheck(malname ,data)
            if loadp.m_conf is None or loadp.m_size is None:
                continue

            offset_conf = loadp.m_conf.start()
            offset_size = loadp.m_size.start()

            offset_conf += 1
            if memory_model == '64bit':
                offset_conf += 26
                while data[offset_conf]!="\x48":
                    offset_conf += 1
                if data[offset_conf] != "\x48":
                    continue

                (config_addr_rva, ) = unpack("=I", data[offset_conf+3:offset_conf+7])
                config_addr = start + offset_conf + 6 - (0xFFFFFFFF - config_addr_rva)
            else:
                while data[offset_conf]!="\xBE" and data[offset_conf]!="\xBF":
                    offset_conf += 1
                if data[offset_conf] != "\xBE" and data[offset_conf] != "\xBF":
                    continue
                (config_addr, ) = unpack("=I", data[offset_conf+1:offset_conf+5])

            offset_size -= 1
            while data[offset_size]!="\xBF" and data[offset_size]!="\xBB":
                offset_size -= 1
            if data[offset_size] != "\xBF" and data[offset_size]!="\xBB":
                continue
            (config_size, ) = unpack("=I", data[offset_size+1:offset_size+5])

            if config_addr < start:
                continue
            outfd.write("{0}\n".format(delim))
            outfd.write("Derusbi Config (Address: 0x%04x):\n\n" % config_addr )
            config_addr -= start
            config_data = data[config_addr:config_addr+config_size]
            outfd.write("Process: %s (%d)\n\n" % (task.ImageFileName, task.UniqueProcessId))
            self.parse_config(config_data, config_size, config_addr, outfd)

class agtidConfig(apt17Scan):
    "Parse the Agtid configuration"

    def parse_config(self, cfg_blob, cfg_sz, cfg_addr, outfd):
        server = unpack_from('<44s', cfg_blob, 0x0)[0]
        port = unpack_from('<I', cfg_blob, 0x2c)[0]
        version = unpack_from('<16s', cfg_blob, 0x30)[0]
        id = unpack_from('<12s', cfg_blob, 0x40)[0]
        run_count = unpack_from('<I', cfg_blob, 0x4C)[0]
        sleeptime = unpack_from('<I', cfg_blob, 0x50)[0]

        ## config write
        outfd.write("[Agtid Config Info]\n")
        outfd.write("Server\t\t: %s\n" % server.split('\0')[0])
        outfd.write("Port\t\t: %i\n" % port)
        outfd.write("Version\t\t: %s\n" % version.split('\0')[0])
        outfd.write("ID\t\t: %s\n" % id.split('\0')[0])
        outfd.write("Running count\t: %i\n" % run_count)
        outfd.write("Sleep time\t: %i\n" % sleeptime)

    def render_text(self, outfd, data):

        delim = '-' * 70

        for task, start, malname in data:
            if "Agtid" in str(malname):
                proc_addr_space = task.get_process_address_space()

                data = proc_addr_space.zread(start, vad_ck().get_vad_end(task, start)-start)

                loadp = patternCheck(malname ,data)
                if loadp.m_conf is None:
                    continue

                offset_conf = loadp.m_conf.start()
                config_size = 84

                offset_conf += 1
                while data[offset_conf]!="\xBE" and data[offset_conf]!="\xBF":
                    offset_conf += 1
                if data[offset_conf]!="\xBE" and data[offset_conf]!="\xBF":
                    continue

                # get address
                (config_addr, ) = unpack("=I", data[offset_conf+1:offset_conf+5])

                if config_addr < start:
                    continue
                outfd.write("{0}\n".format(delim))
                outfd.write("Agtid Config (Address: 0x%04x):\n\n" % config_addr )
                config_addr -= start
                config_data = data[config_addr:config_addr+config_size]
                outfd.write("Process: %s (%d)\n\n" % (task.ImageFileName, task.UniqueProcessId))
                if len(config_data) > 0:
                    self.parse_config(config_data, config_size, config_addr, outfd)


class hikitConfig(apt17Scan):
    "Parse the Hikit configuration"

    def parse_config(self, cfg_blob, cfg_sz, cfg_addr, outfd):
        listenport = []
        ready = []
        sockets = []
        events = []
        thread = []

        proxyname = unpack_from('<64s', cfg_blob, 0)[0]
        proxytype = unpack_from('<I', cfg_blob, 0x40)[0]
        proxyport = unpack_from('<I', cfg_blob, 0x44)[0]
        proxyuser = unpack_from('<32s', cfg_blob, 0x48)[0]
        proxypass = unpack_from('<32s', cfg_blob, 0x68)[0]
        id = unpack_from('<64s', cfg_blob, 0x88)[0]
        server1 = unpack_from('<64s', cfg_blob, 0xC8)[0]
        port1 = unpack_from('<I', cfg_blob, 0x108)[0]
        c2val1 = unpack_from('<I', cfg_blob, 0x10C)[0]
        server2 = unpack_from('<64s', cfg_blob, 0x110)[0]
        port2 = unpack_from('<I', cfg_blob, 0x150)[0]
        c2val3 = unpack_from('<I', cfg_blob, 0x154)[0]
        for i in xrange(10):
            listenport.append(unpack_from('<I', cfg_blob, 0x158 + (i * 20))[0])
        for i in xrange(10):
            ready.append(unpack_from('<L', cfg_blob, 0x15C + (i * 20))[0])
        for i in xrange(10):
            sockets.append(unpack_from('<L', cfg_blob, 0x160 + (i * 20))[0])
        for i in xrange(10):
            events.append(unpack_from('<L', cfg_blob, 0x164 + (i * 20))[0])
        for i in xrange(10):
            thread.append(unpack_from('<L', cfg_blob, 0x168 + (i * 20))[0])
        starttime = unpack_from('<I', cfg_blob, 0x220)[0]
        stoptime = unpack_from('<I', cfg_blob, 0x224)[0]
        workday = unpack_from('<h', cfg_blob, 0x228)[0]
        yy = unpack_from('<h', cfg_blob, 0x22A)[0]
        mm = unpack_from('<h', cfg_blob, 0x22C)[0]
        dd = unpack_from('<h', cfg_blob, 0x230)[0]
        h = unpack_from('<h', cfg_blob, 0x232)[0]
        m = unpack_from('<h', cfg_blob, 0x234)[0]
        s = unpack_from('<h', cfg_blob, 0x236)[0]
        if unpack_from('<I', cfg_blob, 0x23C)[0] == 0:
            hideflag = 'Disable'
        else:
            hideflag = 'Enable'

        ## config write
        outfd.write("[Hikit Config Info]\n")
        outfd.write("ID\t\t: %s, %s\n" % (id.decode('utf-16').split('\0')[0], id.decode('utf-16').split('\0')[1]))
        outfd.write("Proxy setting\n")
        outfd.write("   Type\t\t: %i\n" % proxytype)
        outfd.write("   Server\t: %s\n" % proxyname.split('\0')[0])
        outfd.write("   Port\t\t: %i\n" % proxyport)
        outfd.write("   User\t\t: %s\n" % proxyuser.split('\0')[0])
        outfd.write("   Password\t: %s\n" % proxypass.split('\0')[0])
        outfd.write("Server setting1\n")
        outfd.write("   Server\t: %s\n" % server1.decode('utf-16').split('\0')[0])
        outfd.write("   Port\t\t: %i\n" % port1)
        outfd.write("Server setting2\n")
        outfd.write("   Server\t: %s\n" % server2.decode('utf-16').split('\0')[0])
        outfd.write("   Port\t\t: %i\n" % port2)
        for i in xrange(10):
            if sockets[i] not in [0, 0xffffffff]:
                outfd.write("Listening Port %i\n" % i)
                outfd.write("   Port\t\t: %i\n" % listenport[i])
                outfd.write("   Ready\t: %x\n" % ready[i])
                outfd.write("   socket\t: %x\n" % sockets[i])
                outfd.write("   event\t: %x\n" % events[i])
                outfd.write("   thread\t: %x\n" % thread[i])
        outfd.write("Start Time\t: %02d:%02d:%02d\n" % (starttime / 3600, (starttime % 3600) / 60, starttime % 60))
        outfd.write("Stop Time\t: %02d:%02d:%02d\n" % (stoptime / 3600, (stoptime % 3600) / 60, stoptime % 60))
        outfd.write("Work Day (Enable: 1 Disable: 0)\n")
        outfd.write("   Mon: %i Tue: %i Wed: %i Thu: %i Fir: %i Sat: %i Sun: %i \n" % (workday & 64 / 64, workday & 32 / 32,workday & 16 / 16,workday & 8 / 8,workday & 4 / 4,workday & 2 / 2,workday & 1))
        outfd.write("Sleep Until\t: %d-%d-%d %d:%d:%d\n" % (yy, mm, dd, h, m, s))
        outfd.write("Hide Flag\t: %s\n" % hideflag )

    def render_text(self, outfd, data):

        delim = '-' * 70

        for task, start, malname in data:
            if "Hikit" in str(malname):
                proc_addr_space = task.get_process_address_space()

                data = proc_addr_space.zread(start, vad_ck().get_vad_end(task, start)-start)

                loadp = patternCheck(malname ,data)

                if loadp.m_conf is None:
                    continue

                offset_conf = loadp.m_conf.start()
                config_size = 586

                # get address
                (config_addr, ) = unpack("=I", data[offset_conf+1:offset_conf+5])
                config_addr -= 136

                if config_addr < start:
                    continue
                outfd.write("{0}\n".format(delim))
                outfd.write("Hikit Config (Address: 0x%04x):\n\n" % config_addr )
                config_addr -= start
                config_data = data[config_addr:config_addr+config_size]
                outfd.write("Process: %s (%d)\n\n" % (task.ImageFileName, task.UniqueProcessId))
                self.parse_config(config_data, config_size, config_addr, outfd)
