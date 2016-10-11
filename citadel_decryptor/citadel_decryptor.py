#!/usr/bin/env python
#
# Copyright (C) 2015 JPCERT Coordination Center. All Rights Reserved.
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#

import argparse
import os
import re
import struct
import copy
import pefile
from hashlib import md5
from Crypto.Cipher import AES
import citadel

CITADEL_GET_BASE_CONFIG_PATTERNS = [
    re.compile(".*\x56\xBA(..)\x00\x00\x52\x68(....)\x50\xE8....\x8B\x0D.*", re.DOTALL)]
CITADEL_GET_KEYS_PATTERNS = [
    re.compile(".*\x8D\x85(....)\xE8....\xB9(....)\xE8....\x50\x51\x8D\x45.\x50\xE8....\x6A\x10\x8D\x45.\x50\x8D\x95(....).*", re.DOTALL),
    re.compile(".*\x8D\x85(....)\xE8....\x6A\x20\x68(....)\x8D..\x50\xE8....\x8D\x85(....)\x50.*", re.DOTALL)]
CITADEL_GET_XOR_KEY_PATTERNS = [
    re.compile(".*\x81\x30(....)\x0F\xB6..\x0F\xB6..\x81\x70\x04(....)\x81\x70\x08(....)\x81\x70\x0C(....)\xC1.*", re.DOTALL)]
CITADEL_GET_SALT_PATTERNS = [
    re.compile(".*\x46\x4F\x75\xCE\x33\xF6\xC7\x45\x0C(....).*", re.DOTALL),
    re.compile(".*\x33\xF6\x33\xFF\xC7\x45\x0C(....).*", re.DOTALL)]
CITADEL_GET_FINAL_KEY_PATTERNS = [
    re.compile(".*\x33\xC0\xB9(....)\x3B\xF0.*", re.DOTALL)]
CITADEL_INSTALLED_DATA_SIGNATURES = ["\xDE\xC0\xAD\x0B", "DAVE"]
CITADEL_AES_KEY_OFFSET = 0x8C
MODE_AES_PLUS = 1
MODE_RC4_PLUS = 2
MODE_RC4_PLUS_DOUBLE = 3

parser = argparse.ArgumentParser(description='Citadel decryptor')
parser.add_argument("-n", "--nocheck", action="store_true", dest="no_check", default=None, help="do not check decrypted data")
parser.add_argument("-a", "--array", action="store_true", dest="array", default=None, help="strage array mode")
parser.add_argument("-d", "--decompress", action="store_true", dest="decompress", default=False, help="decompress items of dynamic config")
parser.add_argument("-o", "--out", action="store", dest="out", default=None, help="specify output filename")
parser.add_argument("-D", "--dump", action="store_true", dest="dump", default=False, help="dump base config & installed data")
parser.add_argument("-l", "--login", action="store", dest="login", default=None, help="specify login key")
parser.add_argument("-k", "--key", action="store", dest="key", type=int, default=None, help="specify offset of decrypt key from base config")
parser.add_argument("-x", "--xor", action="store", dest="xor", default=None, help="specify xor key for AES plus decryption")
parser.add_argument("-s", "--salt", action="store", dest="salt", default=None, help="specify RC4 salt")
parser.add_argument("-f", "--final", action="store", dest="final", default=None, help="specify xor key using after Visual Decrypt")
parser.add_argument("-i", "--installed", action="store", dest="installed", default=None, help="specify filename contains installed data")
parser.add_argument("-m", "--mode", action="store", dest="mode", type=int, default=MODE_AES_PLUS, help="decrypt mode: 1 = AES+, 2 = RC4+, 3 = RC4+ * 2")
parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", default=False, help="vervose messages")
parser.add_argument("DAT", help="encrypted file")
parser.add_argument("EXE", help="unpacked main module of Citadel")
args = parser.parse_args()

def search_base_config(pe, data):
    for pattern in CITADEL_GET_BASE_CONFIG_PATTERNS:
        m = re.match(pattern, data)
        if m:
            (bc_size,) = struct.unpack("<h", m.group(1))
            (bc_va,)   = struct.unpack("<I", m.group(2))
            bc_rva     = bc_va - pe.NT_HEADERS.OPTIONAL_HEADER.ImageBase
            bc_ra      = pe.get_physical_by_rva(bc_rva)
            base_config = data[bc_ra:bc_ra+bc_size]
            if args.verbose == True:
                print "[*] found base config at RVA:0x%08x, RA:0x%08x" % (bc_rva, bc_ra)
            return base_config
    return False

def search_keys(pe, data, base_config, login_key, offset, xor_key):
    for pattern in CITADEL_GET_KEYS_PATTERNS:
        m = re.match(pattern, data)
        if m:
            break

    if m == None and login_key == None and offset == None:
        return False, False, False

    if login_key == None:
        (lk_va,)  = struct.unpack("<I", m.group(2))
        lk_rva    = lk_va - pe.NT_HEADERS.OPTIONAL_HEADER.ImageBase
        login_key = pe.get_string_at_rva(lk_rva)
        if args.verbose == True:
            print "[*] found login key: %s" % login_key
    else:
        print "[*] use login key: %s" % login_key

    if offset == None:
        (var_bc,) = struct.unpack("<I", m.group(1))
        var_bc = 0xFFFFFFFF - var_bc + 1
        (var_lk,) = struct.unpack("<I", m.group(3))
        var_lk = 0xFFFFFFFF - var_lk + 1
        offset = var_bc - var_lk
    else:
        print "[*] use key offset 0x%x" % offset
    base_key = {'state': map(ord, list(base_config[offset:offset+0x100])),
                'x'    : ord(base_config[offset+0x100]),
                'y'    : ord(base_config[offset+0x101]),
                'z'    : ord(base_config[offset+0x102])}
    if args.verbose == True:
        print "[*] use RC4 key at (base config + 0x%08x)" % offset

    if xor_key == None:
        for pattern in CITADEL_GET_XOR_KEY_PATTERNS:
            m = re.match(pattern, data)
            if m:
                xor_key = m.group(1) + m.group(2) + m.group(3) + m.group(4)
                break
        if xor_key == None:
            xor_key = "\x00"
        if args.verbose == True:
            print "[*] found following xor key for AES plus:"
            print map(ord, xor_key)
    else:
        print "[*] use following xor key for AES plus:"
        print map(ord, xor_key)

    return login_key, base_key, xor_key

def search_salt(data, salt):
    if salt == None:
        for pattern in CITADEL_GET_SALT_PATTERNS:
            m = re.match(pattern, data)
            if m:
                salt = m.group(1)
                if args.verbose == True:
                    print "[*] found RC4 salt: 0x%08X" % struct.unpack("<I", salt)
                break
    else:
        salt = struct.pack("<I", int(salt, 16))
        print "[*] use RC4 salt: 0x%08X" % struct.unpack("<I", salt)
    return salt

def search_final_key(data, final_key):
    if final_key == None:
        for pattern in CITADEL_GET_FINAL_KEY_PATTERNS:
            m = re.match(pattern, data)
            if m:
                final_key = m.group(1)
                if args.verbose == True:
                    print "[*] found xor key using after Visual Decrypt: 0x%08X" % struct.unpack("<I", final_key)
                break
    else:
        final_key = struct.pack("<I", int(final_key, 16))
        print "[*] use xor key using after Visual Decrypt: 0x%08X" % struct.unpack("<I", final_key)
    return final_key

def get_params(image):
    pe = pefile.PE(image)
    fp = open(image, "rb")
    data = fp.read()
    fp.close()

    tmp = search_base_config(pe, data)
    if tmp == False:
        print "[!] base config search failed"
        return False, False, False, False, False, False
    base_config = ""
    for i in range(0, len(tmp)):
        base_config += chr(ord(tmp[i]) ^ ord(pe.sections[2].get_data()[i]))

    login_key, base_key, xor_key = search_keys(pe, data, base_config, args.login, args.key, args.xor)
    if login_key == False and base_key == False:
        print "[!] key search failed"

    salt = search_salt(data, args.salt)
    if salt == False:
        print "[!] salt search failed"

    final_key = search_final_key(data, args.final)

    return base_config, login_key, base_key, xor_key, salt, final_key

def rc4_plus_init(key, salt):
    enc = []
    for i in range(0, 256):
        enc.append(i)
    prev_target = 0
    for i in range(0, 256):
        target = (ord(key[i%len(key)]) + enc[i] + prev_target) & 0xFF
        tmp = enc[i]
        enc[i] = enc[target]
        enc[target] = tmp
        prev_target = target
    for i in range(0, 256):
        salt_part1 = ord(salt[i%len(salt)]) & 0x07
        salt_part2 = ord(salt[i%len(salt)]) >> 0x03
        if salt_part1 == 0:
            enc[i] = ~enc[i]
        elif salt_part1 == 1:
            enc[i] = enc[i] ^ salt_part2
        elif salt_part1 == 2:
            enc[i] += salt_part2
        elif salt_part1 == 3:
            enc[i] -= salt_part2
        elif salt_part1 == 4:
            enc[i] = (enc[i] >> (salt_part2%8)) | (enc[i] << (8-salt_part2%8))
        elif salt_part1 == 5:
            enc[i] = (enc[i] << (salt_part2%8)) | (enc[i] >> (8-salt_part2%8))
        elif salt_part1 == 6:
            enc[i] += 1
        elif salt_part1 == 7:
            enc[i] -= 1
        enc[i] = enc[i] & 0xFF
    return enc

def rc4_plus_decrypt(login_key, base_key, buf):
    S1 = base_key['state']
    S2 = map(ord, login_key)
    out = ""
    i = j = k = 0
    for c in buf:
        i = (i + 1) & 0xFF
        j = (j + S1[i]) & 0xFF
        S1[i], S1[j] = S1[j], S1[i]
        out += chr((ord(c) ^ S1[(S1[i]+S1[j])&0xFF]) ^ S2[k%len(S2)])
        k += 1
    return out

def unpack_rc4_plus(login_key, base_key, salt, rc4_key, data):
    if rc4_key == None:
        base_key['state'] = rc4_plus_init(rc4_plus_decrypt(login_key, base_key, md5(login_key).digest()), salt)
    else:
        base_key['state'] = rc4_key
    if args.verbose == True:
        print "[*] use following RC4 keystream:"
        print base_key['state']

    out = rc4_plus_decrypt(login_key, base_key, data)
    return out

def unpack_aes_plus(login_key, base_key, xor_key, aes_key, data):
    if aes_key == None:
        aes_key = rc4_plus_decrypt(login_key, base_key, md5(login_key).digest())
    if args.verbose == True:
        print "[*] use following AES key:"
        print map(ord, aes_key)

    aes = AES.new(aes_key)
    tmp = aes.decrypt(data)

    out = ""
    for i in range(len(tmp)):
        out += chr(ord(tmp[i]) ^ ord(xor_key[i%len(xor_key)]))

    return out

def unpack(login_key, base_key, xor_key, salt, final_key, data, mode, aes_key=None, rc4_key=None):
    if mode == MODE_AES_PLUS:
        if args.verbose == True:
            print "[*] try to AES+ decryption"
        tmp = unpack_aes_plus(login_key, base_key, xor_key, aes_key, data)
    elif mode == MODE_RC4_PLUS:
        if args.verbose == True:
            print "[*] try to RC4+ decryption"
        tmp = unpack_rc4_plus(login_key, base_key, salt, rc4_key, data)
    elif mode == MODE_RC4_PLUS_DOUBLE:
        if args.verbose == True:
            print "[*] try to RC4+ double decryption"
        header_size = struct.unpack("<L", data[:4])[0]
        tmp = unpack_rc4_plus(login_key, base_key, salt, rc4_key, data[4:header_size])
        rc4_key = map(ord, tmp[0x1C-4:0x1C-4+0x100])
        out = unpack_rc4_plus(login_key, base_key, salt, rc4_key, data[header_size:])
        return out
    else:
        print "[!] unknown decryption mode: %d" % mode
        return False

    # Visual Decrypt
    tmp2 = ""
    for i in reversed(range(1, len(tmp))):
        tmp2 += chr(ord(tmp[i]) ^ ord(tmp[i-1]))
    tmp2 += tmp[0]
    tmp2 = tmp2[::-1]

    # Additonal XOR used by new version of Citadel
    if final_key != None:
        out = ""
        key1 = final_key
        key2 = tmp2[:0x20]
        tmp3 = tmp2[0x20:]
        for i in range(len(tmp3)):
            out += chr(ord(tmp3[i]) ^ ord(key1[i%4]) ^ ord(key2[i%32]))
        out = key2 + out
    else:
        out = tmp2

    return out

def get_installed_data(base_key, login_key, salt, installed, image):
    pe = pefile.PE(image)
    fp = open(image, "rb")
    data = fp.read()
    fp.close()

    fp = open(installed, "rb")
    installed = fp.read()
    fp.close()

    base_config = search_base_config(pe, data)
    state = rc4_plus_init(base_config, salt)

    overlay = None
    for i in range(0, len(installed)):
        key = {'state': copy.copy(state)}
        if rc4_plus_decrypt(login_key, key, installed[i:i+4]) in CITADEL_INSTALLED_DATA_SIGNATURES:
            key['state'] = copy.copy(state)
            overlay = rc4_plus_decrypt(login_key, key, installed[i:i+0x400])
            if args.verbose == True:
                print "[*] found installed data at RA:0x%08x" % i
            break
    if overlay == None:
        return False
    crc32, size = struct.unpack("<IH", overlay[4:10])
    installed_data = rc4_plus_decrypt(login_key, base_key, overlay[10:10+size])
    return installed_data

def main():
    print "[*] start to decrypt %s" % args.DAT
    if args.out != None:
        out_file = args.out
    else:
        root, ext = os.path.splitext(args.DAT)
        out_file = root + "_decrypted.bin"
    root, ext = os.path.splitext(args.EXE)

    fp = open(args.DAT, "rb")
    data = fp.read()
    fp.close()

    print "[*] get base config & several params"
    base_config, login_key, base_key, xor_key, salt, final_key = get_params(args.EXE)
    if base_config != False and args.dump == True:
        fp = open(root + "_base.bin", "wb")
        fp.write(base_config)
        fp.close()
        print "[*] wrote decrypted base config to %s" % (root + "_base.bin")
    if base_config == False or login_key == False or base_key == False:
        return False

    if args.installed != None:
        print "[*] try to get installed data"
        installed_data = get_installed_data(base_key, login_key, salt, args.installed, args.EXE)
        if installed_data == False:
            print "[!] could not find installed data on %s" % args.installed
            return False
        if args.dump == True:
            fp = open(root + "_installed_data.bin", "wb")
            fp.write(installed_data)
            fp.close()
        aes_key = installed_data[CITADEL_AES_KEY_OFFSET:CITADEL_AES_KEY_OFFSET+0x10]
        (strage_array_key,) = struct.unpack("<I", installed_data[-4:])
        print "[*] try to unpack using installed data"
        if args.verbose == True:
            print "[*] decrypt data using following key:"
            print map(ord, aes_key)
        if args.array == None:
            decrypted = unpack(login_key, base_key, xor_key, salt, final_key, data, MODE_AES_PLUS, aes_key=aes_key)
            if decrypted == False:
                print "[!] decryption failed"
                return False
        else:
            print "[*] strage array mode"
            strage_array = citadel.strage_array(data, strage_array_key)
            if len(strage_array.encrypted_strages) == 0:
                print "[!] parsing strage array failed"
                return False
            decrypted = ""
            for e in strage_array.encrypted_strages:
                decrypted += unpack(login_key, base_key, xor_key, salt, final_key, e.data, MODE_AES_PLUS, aes_key=aes_key)
            if decrypted == "":
                print "[!] decryption failed"
                return False
            args.no_check = True
    else:
        print "[*] try to unpack"
        if args.verbose == True:
            print "[*] decrypt data using following key:"
            print base_key['state']
        decrypted = unpack(login_key, base_key, xor_key, salt, final_key, data, args.mode)
        if decrypted == False:
            print "[!] decryption failed"
            return False

    if args.no_check == True:
        fp = open(out_file, "wb")
        fp.write(decrypted)
        fp.close()
    else:
        print "[*] parse decrypted data...",
        config = citadel.config(decrypted)
        print "OK"
        if args.decompress == True:
            print "[*] decompress decrypted data"
            config.decompress()
        fp = open(out_file, "wb")
        fp.write(config.dump())
        fp.close()
    print "[*] wrote decrypted data to %s" % out_file

if __name__ == '__main__':
    main()
