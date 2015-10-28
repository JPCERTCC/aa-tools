#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#

import struct
import re
import sys, os
from hashlib import md5
from Crypto.Cipher import AES

try:
    from idaapi import *
    from idc import *
except ImportError:
    print '[!] This script can be used in IDA.'
    sys.exit(1)

EMDIVI_KEY_PATTERNS = [re.compile(".*\xC7\x04\$(....)\xE8....\x6A\xFF\x53\x8D\x75\xD4\xC6\x45\xFC\x01.*", re.DOTALL),
                        re.compile(".*\xC7\x04\$(....)\xE8....\xC6\x45\xFC\x01\x8B\x48\x04.*", re.DOTALL),
                        re.compile(".*\xC7\x04\$(....)\xE8....\x6A\x00\x50\x83\xC8\xFF\x8D\x75\xD4\xC6\x45\xFC\x01.*", re.DOTALL),
                        re.compile(".*\x68(....)\x33\xC9\x8D\x55.\xE8....\x83\xC4\x10\x6A\xFF\x53\x8D\x75\xD4.*", re.DOTALL),
                        re.compile(".*\x68(....)\x33\xC9\x8D\x55.\xE8....\x83\xC4\x20\xC6\x45.\x01.*", re.DOTALL),
                        re.compile(".*\x68(....)\x33\xC0\x8D\xBD.\xFF\xFF\xFF\x8D\x8D.*", re.DOTALL)]

def mask32bit(input_dword):
    return input_dword & 0xffffffff

def get_key(version):
    base_addr = Segments().next() | 0x1000

    data = GetManyBytes(base_addr, 0x20000)
    key_str = None
    for pattern in EMDIVI_KEY_PATTERNS:
        m = re.match(pattern, data)
        if m:
            offset =  struct.unpack("L", m.group(1))[0]
            key_str = GetManyBytes(offset, 0x1000)
            key_str = key_str.split("\x00")[0]
            break
    if key_str == None:
        print "[!] could not find base key string!"
        return False
    key = md5(md5(version.encode("base64").strip("\n")).hexdigest() + md5(key_str).hexdigest()).digest()

    if version[:3] == "t19" or (version[:3] == "t20" and (int(version[4:6]) >= 7 and int(version[4:6]) < 26)):
        tmp = ""
        for i, c in enumerate(key.encode('hex')):
            tmp += chr(ord(c) + i)
        tmp = [tmp[i:i+6] for i in xrange(0, len(tmp), 6)][:4]
        key = ""
        for s in tmp:
            pattern = re.compile("^[0-9,a-f,A-F]+")
            m = re.match(pattern, s)
            if m:
                key += struct.pack(">I", int(m.group(0), 16))
            else:
                key += struct.pack(">I", 0)

    elif version[:3] == "t20" and (int(version[4:6]) >= 26 or int(version[4:6]) < 7):
        tmp = ""
        for i, c in enumerate(key.encode('hex')):
            tmp += chr(ord(c) + i)
        key = tmp[:24]

    return key

def get_encrypted_data():
    encrypted_data = []
    # get encrypted base64 strings
    base64_pattern = re.compile("^[0-9,a-z,A-Z\+\/]+={0,2}$")
    strings = Strings()
    for s in strings:
        try:
            string = GetString(s.ea)
            m = re.match(base64_pattern, string)
            if m:
                data = string.decode("base64")
                if len(data) >= 16:
                    encrypted_data.append((s.ea, data))
        except:
            pass

    # get encrypted data from .rdata
    t_seg_start = [ seg_start for seg_start in Segments() if SegName(seg_start) == ".rdata" ][0]
    t_seg_end = GetSegmentAttr(t_seg_start, SEGATTR_END)
    addr = t_seg_start

    while addr < t_seg_end:
        name = Name(addr)
        ref = DfirstB(addr)

        if name[0:4] == "unk_" and ref != BADADDR and GetSegmentAttr(ref, SEGATTR_PERM) == 5:
            next_name = addr+1
            while Name(next_name) == "":
                next_name += 1

            size = next_name - addr
            data = GetManyBytes(addr, size)
            if data != None and len(data) >= 16 and data[-5] != "\x00" and data[-4:] == ("\x00"*4):
                encrypted_data.append((addr, data[:-4]))
            addr = next_name
        else:
            addr += 1

    return encrypted_data

def xxtea_decrypt(key, input_str):
    input_dword = [struct.unpack("<I", input_str[i:i+4])[0] for i in xrange(0, len(input_str), 4)]
    key_dword = struct.unpack(">4I", key)

    last = input_dword[0]
    data1 = mask32bit((0x9E3779B9 * (52 / len(input_dword) + 6)))
    while True:
        idx2 = (data1 >> 2) & 3
        for idx in xrange(len(input_dword)-1, 0, -1):
            work1 = (input_dword[idx - 1] >> 5) ^ mask32bit(4 * last)
            work2 = mask32bit(16 * input_dword[idx - 1] ^ (last >> 3))
            work3 = mask32bit((data1 ^ last) + (input_dword[idx -1] ^ key_dword[idx2 ^ (idx & 3)]))
            work = mask32bit(work3 ^ work2 + work1)
            input_dword[idx] = mask32bit(input_dword[idx] - work)
            last = input_dword[idx]

        work1 = mask32bit((input_dword[-1] >> 5) ^ (last * 4))
        work2 = mask32bit((16 * input_dword[-1]) ^ (last >> 3))
        work = mask32bit(data1 ^ last) + mask32bit(input_dword[-1] ^ key_dword[idx2]) ^ mask32bit(work2 + work1)

        input_dword[0] = mask32bit(input_dword[0] - work)
        last = input_dword[0]
        data1 = mask32bit(data1 - 0x9E3779B9)
        if data1 == 0:
            break

    out = "".join([struct.pack("<I", input_dword[i]) for i in xrange(len(input_dword))])
    return out

def xxtea_encrypt(key, input_str):
    input_dwords = [struct.unpack("<I", input_str[i:i+4])[0] for i in xrange(0, len(input_str), 4)]
    key_dword = struct.unpack(">4I", key)

    out = ""
    for i in range(0, len(input_dwords), 4):
        input_dword = input_dwords[i:i+4]
        data1 = 0
        count = 52 / len(input_dword) + 6
        while count > 0:
            count -= 1
            data1 = mask32bit(data1 + 0x9E3779B9)
            last = input_dword[-1]
            idx2 = (data1 >> 2) & 3
            for idx in xrange(1, len(input_dword)):
                work1 = mask32bit((last >> 5) ^ (4 * input_dword[idx]))
                work2 = mask32bit((16 * last) ^ (input_dword[idx] >> 3))
                work3 = mask32bit((data1 ^ input_dword[idx]) + (last ^ key_dword[idx2^((idx-1)&3)]))
                input_dword[idx-1] = mask32bit(input_dword[idx-1] + (work3 ^ (work2 + work1)))
                last = input_dword[idx-1]

            work1 = mask32bit((last >> 5) ^ (4 * input_dword[0]))
            work2 = mask32bit((16 * last) ^ (input_dword[0] >> 3))
            work = mask32bit((data1 ^ input_dword[0]) + (last ^ key_dword[idx2^(idx&3)]))

            input_dword[-1] = mask32bit(input_dword[-1] + (work ^ (work1 + work2)))
            last = input_dword[-1]
        out += "".join([struct.pack("<I", input_dword[j]) for j in xrange(len(input_dword))])
    return out


def emdivi_decrypt(input_str, key, version):
    salt = "\x10"*16

    if version[:3] == "t17":
        dec = xxtea_decrypt(key, input_str)

    elif version[:3] == "t19" or (version[:3] == "t20" and (int(version[4:6]) >= 7 and int(version[4:6]) < 26)):
        tmp = xxtea_encrypt(key, salt + input_str)
        dec = ""
        for i in xrange(0, len(input_str)):
            dec += chr(ord(tmp[i]) ^ ord(input_str[i]))

    elif version[:3] == "t20" and (int(version[4:6]) >= 26 or int(version[4:6]) < 7):
        aes = AES.new(key)
        tmp = aes.encrypt(salt + input_str[:-len(salt)])
        dec = ""
        for i in xrange(0, len(input_str)):
            dec += chr(ord(tmp[i]) ^ ord(input_str[i]))

    dec = dec[:-ord(dec[-1])]
    out = range(0, len(dec))
    for i in xrange(0, len(dec)):
        if i & 1:
            out[i] = (ord(dec[i]) + i - len(dec)) % 256
        else:
            out[i] = (ord(dec[i]) + len(dec) - i) % 256

    result = "".join(map(chr, out))
    if out[-1] <= len(result) and result[-out[-1]:] == (result[-1] * out[-1]):
        result = result[:-out[-1]]
    return result

def main():
    print "[*] start Emdivi string decryptor"

    version = AskStr("", "input version string of Emdivi")
    if version == None:
        print "[!] cancelled"
        return
    print 'version: "%s"' % version
    if version[0] != 't' or int(version[1:3]) < 17 or int(version[1:3] > 21):
        "[*] unknwon version!"

    print "[*] calculating encryption key"
    key = get_key(version)
    if key == False:
        return
    print 'encryption key: %s' % key.encode('hex')

    print "[*] listing up encrypted strings/data"
    encrypted_data = get_encrypted_data()
    if len(encrypted_data) == 0:
        print "[!] could not find encrypted strings/data!"
        return

    #print "found %d strings/data" % len(encrypted_data)
    print "[*] decrypting..."
    for addr, enc in encrypted_data:
        try:
            decoded_str = emdivi_decrypt(enc, key, version)
            if decoded_str:
                decoded_str.decode('ascii')
                print '0x%08x: "%s"' % (addr, decoded_str)
                MakeRptCmt(addr, '"'+decoded_str+'"')
        except:
            #print "[!] error: %08x, %s" % (addr, enc)
            pass

    print "[*] end Emdivi string decryptor\n"

if __name__ == "__main__":
    main()
