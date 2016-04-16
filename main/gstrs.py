import zipfile
import argparse
import os
import os.path
import binascii
import sys

from libs import dextool


def main(filename):
    strset = dextool.get_strings(filename)
    strlist = list(strset)
    strlist.sort()
    for s in strlist:
        try:
            print(s.decode(errors='ignore'))
        except Exception as e:
            print(s, e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='gstrs', description='')
    parser.add_argument('f', help='apk /dex filename')
    args = parser.parse_args()
    main(args.f)
