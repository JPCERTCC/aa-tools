#!/usr/bin/env python
#
# LICENSE
# the GNU General Public License version 2
#
# Example:
# python wellmess_cookie_decode.py "HgTRdQ2t=64Vm1+mdDjM+lqq1L+yG1KY+ttpjt+c0yWu+4WDJ7+lWL9W+INgn0+mMn%3Am+oFM67.+wh9lp+MsSDK+B7kFU+5%3ApdW+c%3Aa4s.+ypBuf+%3Ayh3a+nNAuS+C0zeX+bmy%3Ay.+6dhp7+fuG%3Ao+a4Aq%3A+GDqKS+6ZXNW.+iNglw+AX0FT+Ot8Ky+so9Ld+b9YeP.+h1JUr+MbW8o+fry4Z+HQ0G%2CR%3A+wn0aG9K.+FdLfzRZ+3zI415R+vBpPR4Z+dZuDhTT+AvYWsFS.+; dMMzvgDU=VZdaeGu+qON73xw+YXlLtZt+ZB6SElT+jdwPGzw.+up0oTlw+hHxFrC5+QaLyyqf+cvc0nMR+LMkulAy.+IyO%3APN1+6GY+++" -k wlLkvOmtVMZmGaReYlKbZA==
#
# python wellmess_cookie_decode.py "c22UekXD=J41lrM+S01+KX29R+As21Sur+%3asRnW+3Eo+nIHjv+o6A7qGw+XQr%3aq+PJ9jaI+KQ7G.+FT2wr+wzQ3vd+3IJXC+lays+k27xd.+di%3abd+mHMAi+mYNZv+Mrp+S%2cV21.+ESollsY+6suRD+%2cx8O1m+%3azc+GYdrw.+FbWQWr+5pO8;1rf4EnE9=+WMyn8+8ogDA+WxR5R.+sFMwDnV+DFninOi+XaP+p4iY+82U.+hZb+QB6+kMBvT9R" -k E5ZxkNAXUaxzRZPbyZkuGA==
#


import argparse
import base64
import sys
import urllib

parser = argparse.ArgumentParser(description="WellMess cookie data decoder")
parser.add_argument("cookiedata", help="cookiedata (without HTTP header)")
parser.add_argument('-k', '--key', action='store', dest='key', help="RC6 key (Base64 strings)")
args = parser.parse_args()


def ROR(x, n, bits = 32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))


def ROL(x, n, bits = 32):
    return ROR(x, bits - n,bits)

def ConvBytesToWords(key):
    array = 4*[0]
    i = 0
    num = 0
    while i < 4:
        num2 = ord(key[num]) & 4294967295
        num += 1
        num3 = ord(key[num]) & 4294967295
        num += 1
        num4 = num3 << 8
        num5 = ord(key[num]) & 4294967295
        num += 1
        num6 = num5 << 16
        num7 = ord(key[num]) & 4294967295
        num += 1
        num8 = num7 << 24
        array[i] = (num2 | num4 | num6 | num8)
        i += 1
    return array


def generateKey(userkey):
    t=44
    w=32
    modulo = 2**w
    encoded = ConvBytesToWords(userkey)
    enlength = len(encoded)

    s=t*[0]
    s[0]=0xB7E15163
    for i in range(1,t):
        s[i]=(s[i-1]+0x9E3779B9)%(2**w)

    v = 3*max(enlength,t)
    A=B=i=j=0

    for index in range(0,v):
        A = s[i] = ROL((s[i] + A + B)%modulo,3,32)
        B = encoded[j] = ROL((encoded[j] + A + B)%modulo,(A+B)%32,32)
        i = (i + 1) % t
        j = (j + 1) % enlength
    return s

def rc6(esentence,s):
    cipher = (len(esentence) / 4)*[0];
    num = 0;
    for i in range(0, len(cipher)):
        num2 = ord(esentence[num]) & 4294967295
        num += 1
        num3 = ord(esentence[num]) & 4294967295
        num += 1
        num4 = num3 << 8;
        num5 = ord(esentence[num]) & 4294967295
        num += 1
        num6 = num5 << 16;
        num7 = ord(esentence[num]) & 4294967295
        num += 1
        num8 = num7 << 24;
        cipher[i] = (num2 | num4 | num6 | num8)
    A = cipher[0]
    B = cipher[1]
    C = cipher[2]
    D = cipher[3]
    r=20
    w=32
    modulo = 2**w
    lgw = 5
    C = (C - s[2*r+3])%modulo
    A = (A - s[2*r+2])%modulo
    for j in range(1,r+1):
        i = r+1-j
        (A, B, C, D) = (D, A, B, C)
        u_temp = (D*(2*D + 1))%modulo
        u = ROL(u_temp,lgw,32)
        t_temp = (B*(2*B + 1))%modulo
        t = ROL(t_temp,lgw,32)
        tmod=t%32
        umod=u%32
        C = (ROR((C-s[2*i+1])%modulo,tmod,32)  ^u)
        A = (ROR((A-s[2*i])%modulo,umod,32)   ^t)
    D = (D - s[1])%modulo
    B = (B - s[0])%modulo
    orgi = []
    orgi.append(A)
    orgi.append(B)
    orgi.append(C)
    orgi.append(D)

    dec = ""
    for i in range(0,len(esentence)):
        dec += chr(orgi[i/4] >> i % 4 * 8 & 255)

    return dec

def main():
    sep = ';'

    data = sep+args.cookiedata

    field = data.split(sep)
    print("[+] {0} field(s) found in data".format(len(field)-1))

    i=1
    encdata = ""
    while i<len(field):
        value = field[i].split("=")
        encdata += value[1]
        i+=1

    encdata = urllib.unquote(encdata)
    encdata = encdata.replace("+", " ").replace("   ", "=").replace(". ", "").replace(" ", "").replace(",", "+").replace(":", "/")

    print("[+] Encoded strings: {0}".format(encdata))
    print("[+] RC6 key: {0}".format(args.key))
    maindata = base64.b64decode(encdata)
    s = generateKey(base64.b64decode(args.key))
    print("[+] Key length: {0}".format(len(s)))
    i = 0
    decode = ""
    try:
        while i < len(maindata):
            orgi = rc6(maindata[i:i+16],s)
            decode += orgi
            i += 16
    except:
        sys.exit("[!] Decrypt error.")

    print("[+] Decrypted strings: {0}".format(decode))

if __name__ == "__main__":
    main()
