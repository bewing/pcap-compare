from __future__ import unicode_literals
from __future__ import print_function
from __future__ import division

import sys


def increment_bytestring(bstring):
    if sys.version_info.major == 3:
        temp_list = []
        for b in bstring:
            temp_list.append(b)
        b[-1] = b[-1] + 1
        return bytes(b)
    else:
        return bstring[0:-1] + chr(ord(bstring[-1]) + 1)  # FIXME: hexwrap
