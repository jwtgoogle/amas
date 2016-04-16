# -*- coding: utf-8 -*-

import argparse
import os
import os.path
import sys
import subprocess
import zipfile
import shutil

from libs.enjarify import parsedex


str_set = set()

def get_apis(filepath):
    tmp_dir = 'dexs'
    cmd = 'dx -JXmx2048m --dex --core-library --multi-dex --output=%s %s' % (tmp_dir, filepath)
    subprocess.call(cmd, shell=True)
    print(filepath, 'convert successfully!')

    dexfile = None
    for parent, dirnames, filenames in os.walk(tmp_dir):
        for filename in filenames:
            dex_path = os.path.join(parent, filename)
            with open(dex_path, 'rb') as f:
                dexfile = parsedex.DexFile(f.read())
            os.remove(dex_path)
    if dexfile is None:
        print("None")
        return
    for i in range(dexfile.string_ids.size):
        str_set.add(dexfile.string(i).decode(errors='ignore') + '\n')


def main(arg):
    rootdir = args.f
    if os.path.isdir(rootdir):
        for parent, dirnames, filenames in os.walk(rootdir):
            for filename in filenames:
                filepath = os.path.join(parent, filename)
                get_apis(filepath)
    elif os.path.isfile(args.f):
        get_apis(args.f)


    filepath = os.path.join(sys.path[1], "cfg", args.o)
    with open(filepath, 'w', encoding='utf-8') as f:
        for s in str_set:
            f.write(s)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='update_apis', description='export apis to files')
    parser.add_argument('f', help='jar folder')
    parser.add_argument('o', help='output file name')
    args = parser.parse_args()
    main(args.f)
