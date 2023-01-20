
from hashlib import md5
import sys

PY2 = sys.version[0] == "2"


def md5_hash(s):
    if PY2:
        return md5(str(s)).hexdigest()
    else:
        return md5(str(s).encode("utf-8")).hexdigest()
