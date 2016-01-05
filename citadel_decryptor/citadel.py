#!/usr/bin/env python
#
# Copyright (C) 2015 JPCERT Coordination Center. All Rights Reserved.
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#

import struct
import copy
import os
from ctypes import *

ITEMF_COMPRESSED        = 0x00000001
ITEMF_COMBINE_ADD       = 0x00010000
ITEMF_COMBINE_OVERWRITE = 0x00020000
ITEMF_COMBINE_REPLACE   = 0x00040000
ITEMF_COMBINE_DELETE    = 0x00080000
ITEMF_IS_OPTION         = 0x10000000
ITEMF_IS_SETTING        = 0x20000000
ITEMF_IS_HTTP_INJECT    = 0x40000000

DIR = os.path.dirname(__file__)
UCL =os.path.join(DIR, "ucl.dll")
DECOMPRESS_MAX_SIZE = 1000000
ITEM_MAX_COUNT = 5000
RANDOM_MAX_COUNT = 0x100

class StrageSizeError(Exception):
    pass

class config:
    def __init__(self, data):
        self.raw_data = copy.copy(data)
        self.header = strage_header(data)
        if self.header.size > len(data):
            raise StrageSizeError
        self.items = self._get_items(data[self.header.header_size:])
    def _get_items(self, data):
        items = []
        offset = 0
        if self.header.count > ITEM_MAX_COUNT:
            raise OverflowError
        for i in range(0, self.header.count):
            tmp = strage_item(data[offset:])
            offset += tmp.size
            items.append(tmp)
        return items
    def show_summary(self):
        j = 0
        for i in self.items:
            print "[*] item[%d]" % j
            i.show_summary()
            j += 1
    def dump(self):
        dump_data = self.header.dump()
        for i in self.items:
            dump_data += i.dump()
        return dump_data
    def decompress(self):
        items_size = 0
        for i in self.items:
            i.decompress()
            items_size += i.size
        return self.header.update(items_size)

class strage_header:
    def __init__(self, data):
        # count random (key) bytes
        for i in range(RANDOM_MAX_COUNT):
            if struct.unpack("<L", data[i:i+4])[0] == len(data):
                self.rand_data = data[:i]
                break
        else:
            raise StrageSizeError
        (self.size, self.flags, self.count) = struct.unpack("<LLL", data[i:i+4*3])
        self.hash = data[i+4*3:i+4*3+0x10].encode("HEX")
        self.header_size = i + 4*3 + 0x10
    def update(self, items_size):
        self.size = self.header_size + items_size
        return True
    def dump(self):
        dump_data= self.rand_data
        dump_data += struct.pack("<LLL", self.size, self.flags, self.count)
        for i in range(0, len(self.hash)/2):
            dump_data += chr(int(self.hash[i*2] + self.hash[i*2+1], 16))
        return dump_data

class strage_item:
    def __init__(self, data):
        (self.id, self.flags, self.data_size, self.data_real_size) = struct.unpack("<LLLL", data[:16])
        self.data = data[16:16+self.data_size]
        self.size = 16 + self.data_size
    def show_summary(self):
        print "Size: %d, Real Size: %d" % (self.data_size, self.data_real_size)
        # show CFGID
        if self.id == 20001:
            print "CFGID_LAST_VERSION",
        elif self.id == 20002:
            print "CFGID_LAST_VERSION_URL",
        elif self.id == 20003:
            print "CFGID_URL_SERVER_0",
        elif self.id == 20004:
            print "CFGID_URL_ADV_SERVERS",
        elif self.id == 20005:
            print "CFGID_HTTP_FILTER",
        elif self.id == 20006:
            print "CFGID_HTTP_POSTDATA_FILTER",
        elif self.id == 20007:
            print "CFGID_HTTP_INJECTS_LIST",
        elif self.id == 20008:
            print "CFGID_DNS_LIST",

        # show ITEMF
        if self.flags & 0x00010000:
            print "ITEMF_COMBINE_ADD",
        if self.flags & 0x00020000:
            print "ITEMF_COMBINE_OVERWRITE",
        if self.flags & 0x00040000:
            print "ITEMF_COMBINE_REPLACE",
        if self.flags & 0x00080000:
            print "ITEMF_COMBINE_DELETE",
        if self.flags & 0x10000000:
            print "ITEMF_IS_OPTION",
        if self.flags & 0x20000000:
            print "ITEMF_IS_SETTING",
        if self.flags & 0x40000000:
            print "ITEMF_IS_HTTP_INJECT",
        if self.flags & 0x00000001:
            print "ITEMF_COMPRESSED",
        print ""
    def decompress(self):
        if self.flags & ITEMF_COMPRESSED == 0:
            return False
        decompressed = self._ucl_decompress(self.data)
        #if len(decompressed) == self.data_real_size:
        #    return False
        self.data = copy.copy(decompressed)
        self.data_size = len(decompressed)
        self.size = 16 + self.data_size
        self.flags = self.flags & (0xFFFFFFFF - ITEMF_COMPRESSED)
        return self.data_size
    def dump(self):
        dump_data = struct.pack("<LLLL", self.id, self.flags, self.data_size, self.data_real_size)
        dump_data += self.data
        return dump_data
    def _ucl_decompress(self, data):
        ucl = cdll.LoadLibrary(UCL)
        compressed = c_buffer(data)
        decompressed = c_buffer(DECOMPRESS_MAX_SIZE)
        decompressed_size = c_int()
        result = ucl.ucl_nrv2b_decompress_le32(pointer(compressed), c_int(len(compressed.raw)), pointer(decompressed), pointer(decompressed_size))
        del ucl
        return decompressed.raw[:decompressed_size.value-1]

class strage_array:
    def __init__(self, data, key):
        self.key = key
        self.encrypted_strages = []
        while len(data) > 5:
            try:
                e = encrypted_strage(data, self.key)
            except:
                break
            data = data[e.size:]
            self.encrypted_strages.append(e)
    def show_summary(self):
        i = 0
        for e in self.encrypted_strages:
            print "[*] Array[%d]" % j
            e.show_summary()
            i += 1
    def dump(self):
        dump_data = ""
        for e in self.encrypted_strages:
            dump_data += e.dump(self.key)
        return dump_data

class encrypted_strage:
    def __init__(self, data, xor_key):
        self.data_size, self.flag = struct.unpack("<LB", data[:5])
        self.data_size ^= xor_key
        self.size = 5 + self.data_size
        if self.data_size > (len(data)-5):
            raise StrageSizeError
        self.data = copy.copy(data[5:5+self.data_size])
    def show_summary(self):
        print "Size: %d" % self.data_size
    def dump(self, key):
        size = self.data_size ^ key
        dump_data = struct.unpack("<LB", size, self.flag)
        dump_data += self.data
        return dump_data
