#!/usr/bin/env python
#
# LICENSE
# the GNU General Public License version 2
#

import sys
import pefile
import re
import argparse
from struct import unpack, unpack_from

# MZ Header
MZ_HEADER = b"\x4D\x5A\x90\x00"

# Resource pattern
RESOURCE_PATTERNS = [re.compile("\x50\x68(....)\x68(.)\x00\x00\x00(.)\xE8", re.DOTALL),
                     re.compile("(.)\x68(...)\x00\x68(.)\x00\x00\x00\x6A\x00\xE8(....)\x83(..)\xC3", re.DOTALL),
                     re.compile("(.)\x68(...)\x00\x68(.)\x00\x00\x00\x50\xE8(....)\x83(..)\xC3", re.DOTALL),
                     re.compile("\x04(.....)\x68(.)\x00\x00\x00\x6A\x00\xE8", re.DOTALL),
                     re.compile("\x56\xBE(....)\x56\x68(.)\x00\x00\x00\x6A\x00\xE8", re.DOTALL),
                     re.compile("\x53\x68(....)\x6A(.)\x56\xFF", re.DOTALL)]

# RC4 key pattern
RC4_KEY_PATTERNS = [re.compile("\x80\x68\x80\x00\x00\x00\x50\xC7\x40", re.DOTALL),
                    re.compile("\x80\x68\x80\x00\x00\x00(...)\x50\x52\x53\xC7\x40", re.DOTALL)]
RC4_KEY_LENGTH = 0x80

# Config pattern
CONFIG_PATTERNS = [re.compile("\xC3\x90\x68(....)\xE8(....)\x59\x6A\x01\x58\xC3", re.DOTALL),
                   re.compile("\x6A\x04\x68(....)\x8D(.....)\x56\x50\xE8", re.DOTALL)]
CONFIG_SIZE = 0x8D4

parser = argparse.ArgumentParser(description="TSCookie Config Parser")
parser.add_argument("file", type=str, metavar="FILE", help="TSCookie EXE file")
args = parser.parse_args()


# RC4
def rc4(data, key):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))

    return ''.join(out)


# helper function for formatting string
def __format_string(data):
    return data.split("\x00")[0]


# Parse config
def parse_config(config):
    print("\n[Proxy settings]")
    print("{0}\n".format("-" * 50))
    for i in xrange(4):
        if config[0x10 + 0x100 * i] != "\x00":
            print("Server name  : {0}".format(__format_string(unpack_from("<240s", config, 0x10 + 0x100 * i)[0].decode("utf-16"))))
            print("     port 1  : {0}".format(unpack_from("<H", config, 0x4 + 0x100 * i)[0]))
            print("     port 2  : {0}".format(unpack_from("<H", config, 0x8 + 0x100 * i)[0]))
    if config[0x400] != "\x00":
        print("Proxy server : {0}".format(__format_string(unpack_from("<128s", config, 0x400)[0].decode("utf-16"))))
        print("        port : {0}".format(unpack_from("<H", config, 0x480)[0]))
    print("ID           : {0}".format(__format_string(unpack_from("<256s", config, 0x500)[0].decode("utf-16"))))
    print("KEY          : 0x{0:X}".format(unpack_from(">I", config, 0x604)[0]))
    print("Sleep time   : {0} (s)".format(unpack_from("<H", config, 0x89C)[0]))


# Decode resource
def decode_resource(rc_data, key_end, fname):
    try:
        enc_data = rc_data[:-RC4_KEY_LENGTH]
        rc4key = rc_data[-RC4_KEY_LENGTH:-4] + key_end
        dec_data = rc4(enc_data, rc4key)
        open(fname, "wb").write(dec_data)
        print("[*] Successful decoding resource : {0}".format(fname))
    except:
        sys.exit("[!] Faild to resource decoding.")
    return dec_data


# Find RC4 key
def load_rc4key(data):
    for pattern in RC4_KEY_PATTERNS:
        mk = re.search(pattern, data)
        key_end = ""
        if mk:
            key_end = data[mk.end() + 1:mk.end() + 5]
            print("[*] Found RC4 key : 0x{0:X}".format(unpack(">I", key_end)[0]))
            break
    return key_end


# Find and load resource
def load_resource(pe, data):
    for pattern in RESOURCE_PATTERNS:
        mr = re.search(pattern, data)
        if mr:
            try:
                (resource_name_rva, ) = unpack("=I", data[mr.start() + 2:mr.start() + 6])
                rn_addr = pe.get_physical_by_rva(resource_name_rva - pe.NT_HEADERS.OPTIONAL_HEADER.ImageBase)
                resource_name = data[rn_addr:rn_addr + 4]
                resource_id = ord(unpack("c", data[mr.start() + 7])[0])
                if resource_id > 200:
                    resource_id = ord(unpack("c", data[mr.start() + 8])[0])
                if resource_id == 104:
                    resource_id = ord(unpack("c", data[mr.start() + 21])[0])
                break
            except:
                sys.exit("[!] Faild to load resource id.")
    if not mr:
        sys.exit("[!] Resource id not found.")

    for idx in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(idx.name) in str(resource_name):
            for entry in idx.directory.entries:
                if entry.id == resource_id:
                    try:
                        data_rva = entry.directory.entries[0].data.struct.OffsetToData
                        size = entry.directory.entries[0].data.struct.Size
                        rc_data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                        print("[*] Found resource : {0}({1})".format(str(idx.name), entry.id))
                    except:
                        sys.exit("[!] Faild to load resource.")

    return rc_data


def main():
    pe = pefile.PE(args.file)
    with open(args.file, "rb") as fb:
        data = fb.read()

    rc_data = load_resource(pe, data)
    key_end = load_rc4key(data)
    dec_data = decode_resource(rc_data, key_end, args.file + ".decode")

    dll_index = dec_data.find(MZ_HEADER)
    if dll_index:
        dll_data = dec_data[dll_index:]
        dll = pefile.PE(data=dll_data)
        print("[*] Found main DLL : 0x{0:X}".format(dll_index))
    else:
        sys.exit("[!] DLL data not found in decoded resource.")

    for pattern in CONFIG_PATTERNS:
        mc = re.search(pattern, dll_data)
        if mc:
            try:
                (config_rva, ) = unpack("=I", dll_data[mc.start() + 3:mc.start() + 7])
                config_addr = dll.get_physical_by_rva(config_rva - dll.NT_HEADERS.OPTIONAL_HEADER.ImageBase)
                enc_config_data = dll_data[config_addr:config_addr + CONFIG_SIZE]
                print("[*] Found config data : 0x{0:X}".format(config_rva))
            except:
                sys.exit("[!] Config data not found in DLL.")

    for pattern in RESOURCE_PATTERNS:
        mr2 = re.search(pattern, dll_data)

    if mr2:
        print("[*] Found resource in main DLL.")
        rc2_data = load_resource(dll, dll_data)
        key_end = load_rc4key(dll_data)
        decode_resource(rc2_data, key_end, args.file + ".2nd.decode")

    try:
        enc_config = enc_config_data[4:]
        rc4key = enc_config_data[:4]
        config = rc4(enc_config, rc4key)
        open(args.file + ".config", "wb").write(enc_config_data)
        print("[*] Successful decoding config: {0}".format(args.file + ".config"))
    except:
        sys.exit("[!] Faild to decoding config data.")

    parse_config(config)

    print("\n[*] Done.")

if __name__ == "__main__":
    main()
