# Searching the ImpFuzzy and Imphash for Volatility
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#
# How to use:
# 1. cd "Volatility Folder"
# 2. mv impfuzzy.py volatility/plugins
# 3. python vol.py [ imphashlist | imphashsearch | impfuzzy ] -f
#    images.mem --profile=Win7SP1x64

import os
import pefile
import hashlib
import volatility.obj as obj
import volatility.debug as debug
import volatility.utils as utils
import volatility.cache as cache
import volatility.win32.tasks as tasks
import volatility.win32.modules as modules
import volatility.plugins.procdump as procdump
import volatility.plugins.malware.impscan as impscan
import volatility.plugins.malware.malfind as malfind

try:
    import pyimpfuzzy
    import impfuzzyutil
    has_pyimpfuzzy = True
except ImportError:
    has_pyimpfuzzy = False


class SearchImp(impscan.ImpScan):

    def get_apilist(self, pid, addr_space, base, task, task_space):

        if not task_space:
            return None

        all_mods = list(task.get_load_modules())

        base_address = base
        for vad in task.VadRoot.traverse():
            if base_address >= vad.Start and base_address <= vad.End:
                size_to_read = vad.Length

        if not task_space.is_valid_address(base_address):
            return None

        data = task_space.zread(base_address, size_to_read)
        apis = self.enum_apis(all_mods)
        addr_space = task_space

        # This is a dictionary of confirmed API calls.
        calls_imported = dict(
            (iat, call)
            for (_, iat, call) in self.call_scan(addr_space, base_address, data)
            if call in apis
        )

        impstrs = []
        for iat, call in sorted(calls_imported.items()):
            mod_name, func_name = self._original_import(
                str(apis[call][0].BaseDllName or ""),
                apis[call][1])
            impstrs.append("%s.%s" %
                           (mod_name.lower().split(".")[0], func_name.lower()))

        if len(impstrs) != 0:
            return ",".join(impstrs)
        else:
            return None


class ImpHashList(procdump.ProcDump, malfind.Malfind):
    """Listing the Import Hash(imphash)"""

    def __init__(self, config, *args, **kwargs):
        procdump.ProcDump.__init__(self, config, *args, **kwargs)
        config.add_option("FASTMODE", default=False, action="store_true",
                          help="Use Fast scan mode (Not use impscan)")

    def detect_injection_proc(self, proc, space):
        detects = []
        for vad, address_space in proc.get_vads(vad_filter=proc._injection_filter):
            if self._is_vad_empty(vad, address_space):
                continue
            if obj.Object("_IMAGE_DOS_HEADER", offset=vad.Start, vm=address_space).e_magic != 0x5A4D:
                continue
            detects.append([vad.Start, address_space])

        return detects

    def calc_hash(self, pe_data, addr_space, base, proc, space):
        try:
            pe = pefile.PE(data=pe_data)
            hash_result = pe.get_imphash()
        except:
            hash_result = "Error: This file is not PE file imphash"

        try:
            fuzzy_result = pyimpfuzzy.get_impfuzzy_data(pe_data)
        except:
            fuzzy_result = "Error: This file is not PE file impfuzzy"

        if not hash_result and not self._config.FASTMODE:
            pid = proc.UniqueProcessId
            simp = SearchImp(self._config)
            apilists = simp.get_apilist(pid, addr_space, base, proc, space)
            if apilists is not None:
                hash_result = hashlib.md5(apilists).hexdigest()
                fuzzy_result = impfuzzyutil.hash_data(apilists)
            else:
                hash_result = ""
                fuzzy_result = ""

        return hash_result, fuzzy_result

    def calculate(self):
        addr_space = utils.load_as(self._config)

        data = self.filter_tasks(tasks.pslist(addr_space))

        for proc in data:
            space = proc.get_process_address_space()
            if space == None:
                continue

            mods = dict((mod.DllBase.v(), mod)
                        for mod in proc.get_load_modules())

            for start, size in self.detect_injection_proc(proc, space):
                pe_file = obj.Object("_IMAGE_DOS_HEADER",
                                     offset=start, vm=size)
                dataset = []
                for offset, code in pe_file.get_image(unsafe=self._config.UNSAFE,
                                                      memory=self._config.MEMORY,
                                                      fix=self._config.FIX):
                    dataset.append(code)
                data = "".join(dataset)

                hash_result, fuzzy_result = self.calc_hash(
                    data, addr_space, start, proc, space)

                yield proc.obj_offset, proc.ImageFileName, start, "INJECTED CODE", hash_result, fuzzy_result

            for mod in mods.values():
                base = mod.DllBase.v()
                mod_name = mod.BaseDllName

                if not space.is_valid_address(base):
                    result = "Error: DllBase is unavailable (possibly due to paging)"
                else:
                    process_offset = space.vtop(proc.obj_offset)
                    pe_file = obj.Object(
                        "_IMAGE_DOS_HEADER", offset=base, vm=space)
                    dataset = []
                    for offset, code in pe_file.get_image(unsafe=self._config.UNSAFE,
                                                          memory=self._config.MEMORY,
                                                          fix=self._config.FIX):
                        dataset.append(code)
                    data = "".join(dataset)

                hash_result, fuzzy_result = self.calc_hash(
                    data, addr_space, base, proc, space)

                yield proc.obj_offset, proc.ImageFileName, base, str(mod_name or ""), hash_result, fuzzy_result

    def render_text(self, outfd, data):
        self.table_header(outfd,
                          [("Process", "[addrpad]"),
                           ("Name", "20"),
                           ("Module Base", "[addrpad]"),
                           ("Module Name", "20"),
                           ("imphash", "32")])

        for offset, FileName, base, ModName, result, fuzzy_result in data:
            self.table_row(outfd, offset, FileName, base, ModName, result)


class ImpHashSearch(ImpHashList):
    """Searching the Import Hash(imphash)"""

    def __init__(self, config, *args, **kwargs):
        ImpHashList.__init__(self, config, *args, **kwargs)
        config.add_option("IMPHASH", short_option="s", type="string",
                          help="Search single imphash value")
        config.add_option("IMPHASHLIST", short_option="i", type="string",
                          help="Search imphash list file")

    def render_text(self, outfd, data):
        self.table_header(outfd,
                          [("Process", "[addrpad]"),
                           ("Name", "20"),
                           ("Module Base", "[addrpad]"),
                           ("Module Name", "20"),
                           ("imphash", "32")])

        if self._config.IMPHASHLIST is not None:
            hashlist = []
            of = open(self._config.IMPHASHLIST, "r")
            lines = of.readlines()
            for line in lines:
                hashlist.append(line.rstrip())

        for offset, FileName, base, ModName, result, fuzzy_result in data:
            if self._config.IMPHASH is not None:
                if result in self._config.IMPHASH and len(result) == 32:
                    self.table_row(outfd, offset, FileName,
                                   base, ModName, result)
            elif self._config.IMPHASHLIST is not None:
                if result in hashlist and len(result) == 32:
                    self.table_row(outfd, offset, FileName,
                                   base, ModName, result)
            else:
                debug.error(
                    "Please set option -s(single imphash) or -i(imphash list file)\n")


class ImpFuzzy(ImpHashList):
    """Comparing or listing the Import Fuzzy Hashing(impfuzzy)"""

    def __init__(self, config, *args, **kwargs):
        ImpHashList.__init__(self, config, *args, **kwargs)
        config.add_option("EXEFILE", short_option="e", type="string",
                          help="Comparing the PE file or direcroty")
        config.add_option("THRESHOLD", short_option="t", type="int",
                          help="Import fuzzy hashing threshold (Default 30)")
        config.add_option("COMPIMPFUZZY", short_option="i", type="string",
                          help="Comparing the list file of impfuzzy")
        config.add_option("LISTIMPFUZZY", short_option="a", default=False, action="store_true",
                          help="Listing the impfuzzy")

    def render_text(self, outfd, data):
        # This is a impfuzzys threshold
        ss_threshold = 30

        if not has_pyimpfuzzy:
            debug.error("pyimpfuzzy must be installed for this plugin")

        files = []
        impfuzzys = []
        impfuzzy = ""
        if self._config.EXEFILE is not None:
            mode = "search"
            if os.path.isdir(self._config.EXEFILE):
                for root, dirs, filenames in os.walk(self._config.EXEFILE):
                    for name in filenames:
                        files.append(os.path.join(root, name))
            elif os.path.isfile(self._config.EXEFILE):
                files.append(self._config.EXEFILE)

            for file in files:
                impfuzzys.append(pyimpfuzzy.get_impfuzzy(file))
                # outfd.write("%s Impfuzzy : %s\n" % (file, pyimpfuzzy.get_impfuzzy(file)))
        elif self._config.COMPIMPFUZZY is not None:
            mode = "search"
            of = open(self._config.COMPIMPFUZZY, "r")
            lines = of.readlines()
            for line in lines:
                impfuzzys.append(line.rstrip())
        elif self._config.LISTIMPFUZZY:
            mode = "list"
        else:
            debug.error(
                "Please set option -e (PE file or directory) or -i (impfuzzy hash list file) or -a (Listing the impfuzzy)")

        if self._config.THRESHOLD is not None:
            ss_threshold = self._config.THRESHOLD

        if "search" in mode:
            self.table_header(outfd,
                              [("Process", "[addrpad]"),
                               ("Name", "20"),
                               ("Module Base", "[addrpad]"),
                               ("Module Name",   "20"),
                               ("impfuzzy", "20"),
                               ("Compare", "7")])

            for offset, FileName, base, ModName, hash_result, fuzzy_result in data:
                for impfuzzy in impfuzzys:
                    if not "Error" in fuzzy_result:
                        if pyimpfuzzy.hash_compare(impfuzzy, fuzzy_result) >= ss_threshold:
                            self.table_row(outfd, offset, FileName, base, ModName, fuzzy_result,
                                           pyimpfuzzy.hash_compare(impfuzzy, fuzzy_result))

        if "list" in mode:
            self.table_header(outfd,
                              [("Process", "[addrpad]"),
                               ("Name", "20"),
                               ("Module Base", "[addrpad]"),
                               ("Module Name", "20"),
                               ("impfuzzy", "110")])

            for offset, FileName, base, ModName, hash_result, fuzzy_result in data:
                if not "Error" in fuzzy_result:
                    self.table_row(outfd, offset, FileName,
                                   base, ModName, fuzzy_result)
