# impfuzzy for Volatility
  Volatility plugin for comparing the impfuzzy and imphash.  
  This plugin can be used to scan malware in memory image.  
  Imphash see [FireEye Blog](https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html)

## Requirements
  This plugin requires the following modules:

  * pyimpfuzzy https://github.com/JPCERTCC/aa-tools/tree/master/impfuzzy/pyimpfuzzy

## Usage
  Use -h to see help message.
  * impfuzzy - compare or print the impfuzzy
  * imphashlist - print the imphash
  * imphashsearch - search the imphash

### Example Usage
#### Printing The Impfuzzy Hash of Process and Dll Module
```
$ python vol.py -f [image] --profile=[profile] impfuzzy -p [PID] -a
```
#### Searching The Impfuzzy Hash from PE Files
```
$ python vol.py -f [image] --profile=[profile] impfuzzy -e [PE File or Folder]
```
#### Searching The Impfuzzy Hash from Hash List
```
$ python vol.py -f [image] --profile=[profile] impfuzzy -i [Hash List File]
```
#### Printing The Imphash
```
$ python vol.py -f [image] --profile=[profile] imphashlist -p [PID]
```
#### Searching The Imphash
```
$ python vol.py -f [image] --profile=[profile] imphashsearch -i [Hash List]
```
