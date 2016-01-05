# Citadel Decryptor
Data decryption tool for Citadel.

## Requirements
  Citadel Decryptor requires [UCL library](http://www.oberhumer.com/opensource/ucl/) to decompress BinStrage. Please build the library then put "ucl.dll" into the same location as the Citadel Decryptor directory.

  Citadel Decryptor also requires the following Python modules:

  * pefile
  * PyCrypto

## Usage
  Use -h to see help message. More details are described in the following documents:

  * https://www.jpcert.or.jp/present/2014/20140218CODEBLUE-Citadel_en.pdf (English)
  * https://www.jpcert.or.jp/present/2014/20140218CODEBLUE-Citadel_ja.pdf (Japanese)
  * https://www.jpcert.or.jp/magazine/acreport-citadel.html (Japanese)

### Example Usage
#### Decrypting dynamic config

```
> citadel_decryptor.py -d root.xml citadel_main.bin
```

#### Decrypting additional modules

```
> citadel_decryptor.py -m3 -n module.bin citadel_main.bin
```

#### Decrypting files created by Citadel

```
> citadel_decryptor.py -m2 -a -i %APPDATA%\random\random.exe %APPDATA%\random\random.random citadel_main.bin
```
