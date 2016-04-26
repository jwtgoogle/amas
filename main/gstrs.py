import zipfile
import argparse
import os
import os.path
import binascii
import sys
from time import clock

from libs import dextool


def list_strs(filepath):
    strset = dextool.get_strings(filepath)
    if not strset:
        return
    strlist = list(strset)
    strlist.sort()
    for s in strlist:
        try:
            print(s.decode(errors='ignore'))
        except Exception as e:
            print(s, e)

    print()


def main(f):
    if os.path.isfile(f):
        list_strs(f)
    elif os.path.isdir(f):
        for parent, dirnames, filenames in os.walk(f):
            for filename in filenames:
                filepath = os.path.join(parent, filename)
                print(filepath)
                list_strs(filepath)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='gstrs', description='')
    parser.add_argument('f', help='apk /dex filename')
    args = parser.parse_args()

    start = clock()
    main(args.f)
    finish = clock()
    print('%fs' % (finish - start))
