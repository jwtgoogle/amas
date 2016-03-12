# Copyright 2015 acgmohu@gmail.com. All Rights Reserved.
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
import shutil
import os


def main(args):
    rootdir = args.dir
    if not os.path.isdir(rootdir):
        print(rootdir, 'is not a directory.')
        return

    # 逐行读取文件
    with open(args.result, 'r') as f:
        while 1:
            lines = f.readlines(10000)
            if not lines:
                break
            for line in lines:
                if len(line) < 2:
                    continue
                if "-->" in line and 'ok' not in line:
                    print(line.replace('\n', ''))
                    backup(rootdir, line)


def backup(rootdir, line):
    backup_dir = 'backup' + os.sep
    if not os.path.isdir(backup_dir):
        os.mkdir(backup_dir)

    for parent, dirnames, filenames in os.walk(rootdir):
        for filename in filenames:
            if filename in line:
                filepath = os.path.join(parent, filename)
                shutil.move(filepath, backup_dir + filename)
                return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='bksamples', description='根据扫描结果，将命中的样本备份到Backup目录')
    parser.add_argument('dir')
    parser.add_argument('result')
    args = parser.parse_args()
    main(args)
