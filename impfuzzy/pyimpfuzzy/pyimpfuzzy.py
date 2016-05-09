#!/usr/bin/env python

import os
import sys
import pefile
import impfuzzyutil
import ordlookup


def get_impfuzzy(file):
    pe = pefileEx(file)
    apilist, apilen = pe.calc_impfuzzy()

    return impfuzzyutil.hash_data(apilist)

def get_impfuzzy_data(file):
    pe = pefileEx(data=file)
    apilist, apilen = pe.calc_impfuzzy()

    return impfuzzyutil.hash_data(apilist)

def hash_compare(hash1, hash2):
    return impfuzzyutil.compare(hash1, hash2)


class pefileEx(pefile.PE):

    def __init__(self, *args, **kwargs):
        pefile.PE.__init__(self, *args, **kwargs)

    def calc_impfuzzy(self):
        impstrs = []
        exts = ["ocx", "sys", "dll"]
        if not hasattr(self, "DIRECTORY_ENTRY_IMPORT"):
            return ""
        for entry in self.DIRECTORY_ENTRY_IMPORT:
            libname = entry.dll.lower()
            parts = libname.rsplit(".", 1)
            if len(parts) > 1 and parts[1] in exts:
                libname = parts[0]

            for imp in entry.imports:
                funcname = None
                if not imp.name:
                    funcname = ordlookup.ordLookup(
                        entry.dll.lower(), imp.ordinal, make_name=True)
                    if not funcname:
                        raise Exception("Unable to look up ordinal %s:%04x" % (
                            entry.dll, imp.ordinal))
                else:
                    funcname = imp.name

                if not funcname:
                    continue

                impstrs.append("%s.%s" % (libname.lower(), funcname.lower()))

        apilist = ",".join(impstrs)
        return apilist, len(apilist)
