# Copyright (C) 2017 JPCERT Coordination Center. All Rights Reserved.
#
# LICENSE
# Please refer to the LICENSE.txt in the https://github.com/JPCERTCC/aa-tools/
#

import sys,re
from splunklib.searchcommands import dispatch, StreamingCommand, Configuration
from binascii import crc32

filter_1 = re.compile('(http://[\da-z\.-]+\.[a-z\.]{2,6}/[\/\w_\.-]+\?[\da-z]{3,8}=([\da-f]{8})([\da-f]{8})[1-2]{1}\S+)\s', re.IGNORECASE)

@Configuration()
class Datper(StreamingCommand):
    def checkDatper(self,raw_field):
        m1 = filter_1.search(raw_field)
        if m1:
            url = m1.group(1).lower()
            d1 =  m1.group(2).lower()
            d2 =  m1.group(3).lower()
            d1_crc32 = "%08x" % (crc32(d1) & 0xffffffff)
            if d1_crc32 == d2:
                return 'yes'
            else:
                return 'no'
        else:
            return 'no'

    def stream(self, events):
        for event in events:
            event['is_datper'] = self.checkDatper(event['_raw'])
            yield event

if __name__ == '__main__':
    try:
        dispatch(Datper, sys.argv, sys.stdin, sys.stdout, __name__)
    except:
        import traceback,splunk.Intersplunk
        stack =  traceback.format_exc()
        results = splunk.Intersplunk.generateErrorResults("Error : Traceback: " + str(stack))
