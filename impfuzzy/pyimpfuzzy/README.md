# pyimpfuzzy
  Python module for comparing the impfuzzy

  More details are described in the following documents:   
  https://www.jpcert.or.jp/magazine/acreport-impfuzzy.html (Japanese)   
  http://blog.jpcert.or.jp/2016/05/classifying-mal-a988.html (English)

## Requirements
  pyimpfuzzy requires the following modules:

  * pefile 1.2.10-139 or later
  * ssdeep http://ssdeep.sourceforge.net

## Installation

```bash
$ pip install pyimpfuzzy
```
or
```bash
$ sudo python setup.py install
```

## Usage
  * get_impfuzzy - return the impfuzzy hash for a given file
  * get_impfuzzy_data - return the impfuzzy hash for a buffer
  * hash_compare - return the match between 2 hashes

### Example Usage

```python
import pyimpfuzzy
import sys

hash1 = pyimpfuzzy.get_impfuzzy(sys.argv[1])
hash2 = pyimpfuzzy.get_impfuzzy(sys.argv[2])
print "ImpFuzzy1: %s" % hash1
print "ImpFuzzy2: %s" % hash2
print "Compare: %i" % pyimpfuzzy.hash_compare(hash1, hash2)
```
## Archive
  [pyimpfuzzy-0.1.tar.gz](https://pypi.python.org/packages/9b/f9/3abdd7e0e2cbfe3328260c06e38e693d86d54b95e9954a7ca6b953005513/pyimpfuzzy-0.1.tar.gz) sha256 09c997df16c822d88f0aac21e21cdfb7195716e2b24dc6c4554eaa99b7de81da  
  [pyimpfuzzy-0.2.tar.gz](https://pypi.python.org/packages/41/46/f01a1730da6b0a7e91a861b69ce1f79f244487ff1e4c05c30dba5cb22eea/pyimpfuzzy-0.2.tar.gz) sha256 06cfe1588055ceeef839446cea7bac9c08cce8aa2eb1621bc591a97af2729622
