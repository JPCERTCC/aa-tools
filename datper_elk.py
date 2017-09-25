#!/usr/bin/env python
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#

import re
import sys
from binascii import crc32
import json
from elasticsearch import Elasticsearch

filter_1 = re.compile('(http://[\da-z\.-]+\.[a-z\.]{2,6}/[\/\w_\.-]+\?[\da-z]{3,8}=([\da-f]{8})([\da-f]{8})[1-2]{1}\S+)\s', re.IGNORECASE)

def checkDatper(message):
    m1 = filter_1.search(message)
    if m1:
        url = m1.group(1).lower()
        d1 = m1.group(2).lower()
        d2 = m1.group(3).lower()
        d1_crc32 = '%08x' % (crc32(d1.encode('utf-8')) & 0xffffffff)

        if d1_crc32 == d2:
            return 'yes'
        else:
            return 'no'
    else:
        return 'no'

def updateElastic(es_api, index):
    es = Elasticsearch(es_api)
    res = es.search(index=index, body={ 'query': { 'match_all' : {} } })
    for hit in res['hits']['hits']:
        id = hit['_id']
        type = hit['_type']
        message = hit['_source']['message']
        datper = checkDatper(message)
        es.update(index=index, doc_type=type, id=id, body={ 'doc': { 'datper' : datper } })

if __name__ == '__main__':
    if len(sys.argv) > 1:
        updateElastic(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 1:
        result = None
        try:
            result = checkDatper(sys.argv[1])
        except Exception as e:
            result = e.message
        print(result)
