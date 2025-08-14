#---------------------------------------------------------------------------------
# TOOL Name: parse_crossc2beacon_config.py
# JPCERT/CC masubuchi
#---------------------------------------------------------------------------------

import argparse
import sys
import re
import Crypto.Cipher.AES


# Config Structure
CONFIG_TAG = b"\x48\x4f\x4f\x4b" # HOOK
CONFIG_SIZE_OFFSET = 0x4
CONFIG_SIZE_LENGTH = 0x4
CONFIG_DATA_OFFSET = 0x8

# Config Decryption KEY
AES_KEY = b"\x61\x61\x61\x61\x62\x62\x62\x62\x63\x63\x63\x63\x64\x64\x64\x64" # aaaabbbbccccdddd
AES_IV = b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6A\x6B\x6C\x6D\x6E\x6F\x70" # abcdefghijklmnop


def isCharaPrintable(s):
    if s < 0x7e and s >= 0x21:
        return True
    return False


def validateByteAsPrintable(byte):
    # Return '.' if the byte is not printable
    if isCharaPrintable(byte):
        return byte
    else:
        return 0x2e


def hexdumpBytes(inBytes):
    memAddr = 0
    ascii_string = ""
    print("Offset 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F Encode to ASCII")
    for byte in inBytes:
        ascii_string = ascii_string + chr(validateByteAsPrintable(byte))
        if memAddr%0x10 == 0:
            print(format(memAddr, '06X'),end = '')
            print(" " + hex(byte)[2:].zfill(2), end='')
        elif memAddr%0x10 == 0xF:
            print(" " + hex(byte)[2:].zfill(2),end='')
            print(" " + ascii_string)
            ascii_string = ""
        else:
            print(" " + hex(byte)[2:].zfill(2), end='')
        memAddr = memAddr + 1


def byte_to_int(inBytes):
    return int.from_bytes(inBytes, "little")


def search_configtag(filecontent, searchtag):
    config_point = re.search(searchtag, filecontent)
    return config_point.start()


def decrypt_AES128_CBC(data, key, iv):
    cipher = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, iv)
    ct_bytes = cipher.decrypt(data)
    return ct_bytes


def parse_config(decoded_configdata):
    # c2 ip
    c2 = decoded_configdata[4:8]
    c2ip = ""
    for x in c2:
        c2ip += "{}".format(x) + "."
    c2ip = c2ip[:-1]
    # c2 port
    port = byte_to_int(decoded_configdata[8:12])
    
    # pubkey
    pubkey_s = search_configtag(decoded_configdata, b"-----BEGIN.PUBLIC.KEY")
    pubkey_e = search_configtag(decoded_configdata, b"END.PUBLIC.KEY-----")
    pubkey_b = decoded_configdata[pubkey_s:pubkey_e + len("END.PUBLIC.KEY-----")]
    pubkey = pubkey_b.decode(encoding="utf-8")
        
    print(f"\tC2: {c2ip}:{port}\n\tPUBLICKEY: {pubkey}")


def parse_crossc2beacon(data):
    config_offset = search_configtag(data, CONFIG_TAG)
    configsize_b = data[config_offset + CONFIG_SIZE_OFFSET:config_offset + CONFIG_SIZE_OFFSET + CONFIG_SIZE_LENGTH]
    configsize = byte_to_int(configsize_b)

    configdata_b = data[config_offset + CONFIG_DATA_OFFSET:config_offset + CONFIG_DATA_OFFSET + configsize]

    if False: 
        print("[+] Encoded Config Data")
        hexdumpBytes(configdata_b)

    ct_bytes = decrypt_AES128_CBC(configdata_b, AES_KEY, AES_IV)
    
    print("[+] Decoded Config Data")
    hexdumpBytes(ct_bytes)

    print("[+] Config Data")
    parse_config(ct_bytes)


def main():
    parser = argparse.ArgumentParser(description='Decoder')
    parser.add_argument('crossc2beacon', type=argparse.FileType('rb'), default=sys.stdin, help='data')
    args = parser.parse_args()
    data = args.crossc2beacon.read()
    parse_crossc2beacon(data)


if __name__ == '__main__':
    main()
