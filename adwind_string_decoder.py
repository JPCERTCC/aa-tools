#!/usr/bin/env python
#
# Copyright (C) 2016 JPCERT Coordination Center. All Rights Reserved.
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#

import re
import sys
import os
import io
import codecs
import zipfile
import tempfile
import subprocess
import shutil

def usage(decoder_py):
    for s in [
            'Usage:',
            ' python ' + decoder_py + ' "sample.jar"',
            '  - output decoded strings to stdout',
            '',
            ' python ' + decoder_py + ' "sample.jar" "output.jasm"',
            '  - output javap disassembly with decoded strings',
            '',
            ' python ' + decoder_py + ' "sample.jar" "source folder" "output folder"',
            '  - decode strings in decompiled source files etc.',
            '  - non-fully qualified method names are not supported.',
            '',
            'Requirements:',
            ' javap in JDK (Java Development Kit)',
            ' python 2.7 or later is recommended for unzip capability',
            ]:
        print(s)

def interpret_key(jasm):
    key = {}
    func = None
    jasm.seek(0)
    for line in jasm:
        line = line.decode('U8')
        if re.match('[pfcs]', line[0]):
            jclass = False
            for s in line.split():
                if jclass:
                    jclass = s
                    break
                jclass = (s == 'class')
        elif re.match('  public static java\.lang\.String .*\(java\.lang\.String\);', line):
            func = jclass.replace('.', '/') + '.' + line.split()[-1].split('(')[0] + ':(Ljava/lang/String;)Ljava/lang/String;'
            key1 = None
            key2 = None
            jstack = []
            jlocal = [0] * 20
        elif func:
            op = line.split()
            if len(op) < 2:
                continue
            try:
                if op[1] == 'new':
                    jstack.append([])
                elif op[1] == 'newarray':
                    jstack.pop()
                    jstack.append([])
                elif op[1] == 'invokespecial':
                    if re.match('java/lang/(Throwable|Exception)\."<init>":\(\)V', op[5]):
                        jstack.pop()
                    elif op[5] == 'java/lang/StringBuffer."<init>":(Ljava/lang/String;)V':
                        key1 = [jstack.pop()]
                        jstack.pop()
                elif op[1] == 'invokevirtual':
                    if re.match('java/lang/(Throwable|Exception)\.getStackTrace:\(\)\[Ljava/lang/StackTraceElement;', op[5]):
                        jstack.pop()
                        jstack.append([])
                        key2 = []
                    elif op[5] == 'java/lang/StackTraceElement.getClassName:()Ljava/lang/String;':
                        jstack.pop()
                        jstack.append('c')
                    elif op[5] == 'java/lang/StackTraceElement.getMethodName:()Ljava/lang/String;':
                        jstack.pop()
                        jstack.append('m')
                    elif op[5] == 'java/lang/StringBuffer.append:(Ljava/lang/String;)Ljava/lang/StringBuffer;':
                        key1.append(jstack.pop())
                    elif op[5] == 'java/lang/StringBuffer.insert:(ILjava/lang/String;)Ljava/lang/StringBuffer;':
                        s = jstack.pop()
                        key1.insert(jstack.pop(), s)
                    elif op[5] == 'java/lang/String.length:()I':
                        jstack.pop()
                        jstack.append(0)
                    elif op[5] == 'java/lang/String.charAt:(I)C':
                        jstack.pop()
                        jstack.pop()
                        jstack.append(0)
                elif op[1] == 'aaload':
                    jstack.pop()
                    jstack.pop()
                    jstack.append([])
                elif op[1] == 'isub':
                    jstack.pop()
                    jstack.pop()
                    jstack.append(0)
                elif op[1] == 'dup':
                    jstack.append(jstack[len(jstack) - 1])
                elif op[1][:5] == 'dup_x':
                    jstack.insert(len(jstack) - 1 - int(op[1][5:]), jstack[len(jstack) - 1])
                elif op[1] == 'swap':
                    jstack.append(jstack.pop(len(jstack) - 2))
                elif op[1] == 'pop':
                    jstack.pop()
                elif op[1] == 'pop2':
                    jstack.pop()
                    jstack.pop()
                elif op[1][:6] == 'iconst':
                    jstack.append(int(op[1].split('_')[1]))
                elif op[1] == 'ishl':
                    i = jstack.pop()
                    jstack.append(jstack.pop() << i)
                elif op[1] == 'ixor':
                    i = jstack.pop()
                    jstack.append(jstack.pop() ^ i)
                elif op[1][1:6] == 'store':
                    i = op[1].split('_')
                    if len(i) >= 2:
                        i = i[1]
                    else:
                        i = op[2]
                    jlocal[int(i)] = jstack.pop()
                elif op[1][1:5] == 'load':
                    i = op[1].split('_')
                    if len(i) >= 2:
                        i = i[1]
                    else:
                        i = op[2]
                    i = jlocal[int(i)]
                    jstack.append(i)
                    if op[1][:1] == 'i' and i > 0:
                        key2.append(i)
                elif op[1] == 'castore':
                    jstack.pop()
                    jstack.pop()
                    jstack.pop()
                elif re.match('if[egln]', op[1]):
                    jstack.pop()
                elif op[1] == 'areturn':
                    key[func] = ((key1[0] + key1[1] == 'cm'), key2)
                    func = None
            except:
                func = None
    return key

def uchr(i):
    if sys.version_info[0] < 3:
        return unichr(i)
    else:
        return chr(i)

def decode_utf8(buf):
    utf = ''
    pos = 0
    end = len(buf)
    while pos < end:
        c = buf[pos]
        if ord(c) < 0x80:
            utf = utf + c
        else:
            bytes = 6
            while bytes >= 2:
                mask = 0x3f00 >> bytes & 0xfc
                if ord(c) & mask == mask:
                    bits = ord(c) & ~mask
                    for d in buf[pos + 1 : pos + bytes]:
                        bits = bits << 6 | ord(d) & 0x3f
                    utf = utf + uchr(bits)
                    pos = pos + bytes - 1
                    break
                bytes = bytes - 1
        pos = pos + 1
    return utf

class jasm_str:
    def init(self, jclass):
        pass

    def decode(self, ss, op, jclass):
        ss = ss.replace('\\t', '\t')
        ss = ss.replace('\\n', '\n')
        ss = ss.replace('\\r', '\r')
        ss = ss.replace('\\"', '\"')
        return ss

class jconst_pool_str(jasm_str):
    def __init__(self, jar):
        self.jar = zipfile.ZipFile(jar, 'r')
        self.cp_utf = {}
        self.cp_str = {}

    def init(self, jclass):
        jb = self.jar.read(jclass.replace('.', '/') + '.class')
        jc = jb.decode('L1')
        if jc[:4] == b'\xca\xfe\xba\xbe'.decode('L1'):
            self.cp_utf[jclass] = {}
            self.cp_str[jclass] = {}
            pos = 10
            idx = 1
            cnt = (ord(jc[8]) << 8) + ord(jc[9])
            while idx < cnt:
                tag = ord(jc[pos])
                pos = pos + 1
                if tag == 1: #Utf8
                    end = pos + 2 + (ord(jc[pos]) << 8) + ord(jc[pos + 1])
                    pos = pos + 2
                    try:
                        utf = jb[pos:end].decode('U8')
                    except UnicodeDecodeError:
                        utf = decode_utf8(jc[pos:end])
                    self.cp_utf[jclass][idx] = utf
                    pos = end
                elif tag == 8: #String
                    self.cp_str[jclass][idx] = (ord(jc[pos]) << 8) + ord(jc[pos + 1])
                    pos = pos + 2
                elif tag == 7 or tag == 16: #Class,MethodType
                    pos = pos + 2
                elif tag == 15: #MethodHandle
                    pos = pos + 3
                elif tag == 3 or tag == 4 or tag == 9 or tag == 10 or tag == 11 or tag == 12 or tag == 18:
                    pos = pos + 4
                elif tag == 5 or tag == 6: #Long,Double
                    pos = pos + 8
                    idx = idx + 1
                idx = idx + 1

    def decode(self, ss, op, jclass):
        idx = int(op[2][1:].split(';')[0])
        if not idx in self.cp_utf[jclass]:
            idx = self.cp_str[jclass][idx]
        utf = self.cp_utf[jclass][idx]
        return utf

def decode_strings(jasm, key, jstr, out):
    cnt = 0
    sstack = []
    jasm.seek(0)
    for line in jasm:
        line = line.decode('U8')
        end = -1 - (len(line) >=2 and line[-2] == '\r')
        func = None
        if re.match('[pfcs]', line[0]):
            caller_class = False
            for s in line.split():
                if caller_class:
                    caller_class = s
                    jstr.init(caller_class)
                    break
                caller_class = (s == 'class')
        elif re.match('  [a-z].*\(.*\).*;', line):
            end = line.rindex('(')
            pos = line[:end].rindex(' ') + 1
            caller_method = line[pos:end]
            if caller_method == caller_class:
                caller_method = '<init>'
        elif line[:end] == '  static {};':
            caller_method = '<clinit>'
        else:
            op = line.split()
            if len(op) >= 5:
                if op[1][0:3] == 'ldc':
                    i = line.find('// String ')
                    if i >= 0:
                        sstack.append(jstr.decode(line[i + 10 : end], op, caller_class))
                        if len(sstack) > 20:
                            del sstack[0]
                elif op[1] == 'invokestatic':
                    func = op[5]
                    if not '.' in func.split('(')[0]:
                        func = caller_class.replace('.', '/') + '.' + func
                    if func[0] == '"':
                        i = func.rindex('.')
                        func = func[1 : i - 1] + func[i:]
                    if func in key:
                        if key[func][0]:
                            key1 = caller_class + caller_method
                        else:
                            key1 = caller_method + caller_class
                        key2 = key[func][1]
                        key1top = len(key1) - 1
                        key1idx = key1top
                        key2idx = 0
                        ss = sstack.pop()
                        dec = []
                        for c in reversed(ss):
                            c = ord(c) ^ ord(key1[key1idx]) ^ key2[key2idx]
                            c = uchr(c)
                            dec.insert(0, c)
                            key1idx = key1idx - key2idx
                            if key1idx < 0:
                                key1idx = key1top
                            key2idx = key2idx + 1 & 1
                        out.write(line, func, ''.join(dec), ss)
                        cnt = cnt + 1
                    else:
                        func = None
        out.write(line, func, None, None);
    return cnt

class std_writer:
    def write(self, line, func, res, arg):
        if res:
            print(res)

class line_writer(std_writer):
    def __init__(self):
        self.num = 1

    def write(self, line, func, res, arg):
        if res:
            print(str(self.num) + '\t' +  res)
        else:
            self.num = self.num + 1

class jasm_writer(std_writer):
    def __init__(self, jasm):
        self.out = open(jasm, 'wb')

    def write(self, line, func, res, arg):
        if func:
            if res:
                res = res.replace('\n', '\\n')
                res = res.replace('\r', '\\r')
                i = line.index(' // Method')
                self.out.write(line[:i].encode('U8'))
                self.out.write(' // STRING '.encode('U8'))
                self.out.write(res.encode('U8'))
                self.out.write(line[i:].encode('U8'))
        else:
            self.out.write(line.encode('U8'))

class dict_writer(std_writer):
    def __init__(self):
        self.dic = {}

    def write(self, line, func, res, arg):
        if res:
            i = func.replace(':(Ljava/lang/String;)Ljava/lang/String;', '').replace('/', '.') + '("' + arg + '")'
            if i in self.dic and self.dic[i] != res:
                raise KeyError(i + ' : ' + self.dic[i] + ' : ' + res)
            self.dic[i] = res

def replace_strings(dic, src, dst):
    cnt = 0
    os.mkdir(dst)
    for root, dirs, files in os.walk(src):
        for name in dirs:
            os.mkdir(dst + os.path.join(root, name)[len(src):])
        for name in files:
            out = open(dst + os.path.join(root, name)[len(src):], 'wb')
            for line in open(os.path.join(root, name), 'rb'):
                line = line.decode('U8')
                for esc in re.finditer('[a-zA-Z0-9_.\\\\]+?\(".*?[^\\\\](\\\\\\\\)*?"\)', line):
                    esc = esc.group(0)
                    raw = esc.encode('U8').decode('unicode_escape')
                    if raw in dic:
                        line = line.replace(esc, '"' + dic[raw].encode('unicode_escape').decode('U8').replace('"', '\\"') + '"', 1)
                        cnt = cnt + 1
                out.write(line.encode('U8'))
    sys.stderr.write(str(cnt) + ' / ')

def decode_main(argi, jasm):
    key = interpret_key(jasm)
    i = argi
    if len(sys.argv) > i and zipfile.is_zipfile(sys.argv[i]):
        jstr = jconst_pool_str(sys.argv[i])
        i = i + 1
    else:
        jstr = jasm_str()
    if len(sys.argv) > i + 1 and os.path.isdir(sys.argv[i]) and (os.path.isdir(sys.argv[i + 1]) or not os.path.exists(sys.argv[i + 1])):
        out = dict_writer()
        cnt = decode_strings(jasm, key, jstr, out)
        replace_strings(out.dic, sys.argv[i], sys.argv[i + 1])
    elif len(sys.argv) > i:
        out = jasm_writer(sys.argv[i])
        cnt = decode_strings(jasm, key, jstr, out)
    else:
        if sys.version_info[0] < 3:
            sys.stdout = codecs.getwriter('U8')(sys.stdout)
        else:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding = 'U8')
        if argi == 1:
            out = std_writer()
        else:
            out = line_writer()
        cnt = decode_strings(jasm, key, jstr, out)
    sys.stderr.write(str(cnt) + ' strings\n')

def main():
    if len(sys.argv) < 2:
        usage(os.path.basename(sys.argv[0]))
        return
    if zipfile.is_zipfile(sys.argv[1]):
        jar = sys.argv[1]
        jdk = os.getenv('JAVA_HOME')
        if jdk:
            javap = os.path.join(jdk, 'bin', 'javap')
        else:
            javap = 'javap'
        javap = [javap, '-c', '-p', '-J-Dfile.encoding=UTF-8']
        jasm = tempfile.TemporaryFile()
        try:
            dtmp = tempfile.mkdtemp()
            jar = zipfile.ZipFile(jar, 'r')
            fmt = '{0}.class'
            cnt = 0
            for i in jar.namelist():
                if i.endswith('.class'):
                    tmp = open(os.path.join(dtmp, fmt.format(cnt)), 'wb')
                    tmp.write(jar.read(i))
                    tmp.close()
                    cnt = cnt + 1
            sys.stderr.write(str(cnt) + ' classes ...\n')
            subprocess.check_call(javap + [os.path.join(dtmp, fmt.format(i)) for i in range(cnt)], stdout=jasm)
        finally:
            shutil.rmtree(dtmp)
        decode_main(1, jasm)
    else:
        decode_main(2, open(sys.argv[1], 'rb'))

if __name__ == '__main__':
    main()
