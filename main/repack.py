# Copyright 2016 acgmohu@gmail.com. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import os.path
import os
import hashlib
import io
import subprocess
import shutil
import sys

from libs import hashtool


with open(os.path.join(sys.path[1], "cfg", 'smali.txt'), \
        'r', encoding='utf-8') as f:
    clzs = f.readlines()


def repack(filepath, flag=False):
    if flag:
        shutil.copy(filepath, filepath + '_bak')

    # decode
    cmd = 'baksmali %s' % filepath
    print(cmd)
    subprocess.call(cmd, shell=True)

    # remove
    for clz in clzs:
        path = 'out' + os.sep + clz.replace('.', os.sep).strip('\n')
        if os.path.exists(path):
            print('del %s' % path)
            shutil.rmtree(path)

    # repack
    cmd = 'smali out'
    subprocess.call(cmd, shell=True)
    md5 = hashtool.get_md5('classes.dex')
    cmd = 'zip %s classes.dex' % filepath
    subprocess.call(cmd, shell=True)

    # clear
    shutil.rmtree('out')
    os.remove('classes.dex')


def main(args):
    f = args.f
    if os.path.isfile(f):
        repack(f, args.b)
    elif os.path.isdir(f):
        for parent, dirnames, filenames in os.walk(f):
            for filename in filenames:
                filepath = os.path.join(parent, filename)
                repack(filepath, args.b)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='repack', description='repack')
    parser.add_argument('f', help='filename or dirname')
    parser.add_argument('-b', action='store_true', help='backup', required=False)
    args = parser.parse_args()
    main(args)
