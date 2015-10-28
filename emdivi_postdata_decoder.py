#!/usr/bin/env python
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#

import argparse
import urllib

parser = argparse.ArgumentParser(description="Emdivi post data decoder")
parser.add_argument("postdata", help="1st or 2nd postdata (without HTTP header)") 
args = parser.parse_args()

def main():
    if ';' in args.postdata:
        delimiter = ';'
    else:
        delimiter = '&'

    if args.postdata[0] == delimiter:
        fields = args.postdata[1:].split(delimiter)
    else:
        fields = args.postdata.split(delimiter)
    
    print "[*] %d field(s) found in postdata" % len(fields)

    for field in fields:
        name, value = field.split("=")

        xor_key = 0x00
        for c in name:
            xor_key = (ord(c)) ^ xor_key

        dec = ""
        for c in urllib.unquote(value):
            dec += chr(ord(c) ^ xor_key)

        print "\"%s\"\t->\t\"%s\"" % (name, dec)

if __name__ == '__main__':
    main()
