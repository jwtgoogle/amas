# Copyright 2016 acgmohu@gmail.con. All Rights Reserved.
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

android_list = ['Landroid/']


def process_smali(filepath):
    is_mtd = False
    is_del = False
    content = ''
    tmp = ''
    with open(filepath, 'r') as f:
        while 1:
            lines = f.readlines(10000)
            if not lines:
                break
            for line in lines:
                if line.startswith('.field') or line.startswith('# instance fields'):
                    flag = False
                    for s in android_list:
                        if s in line:
                            flag = True
                            break
                    if flag:
                        continue

                if line.startswith('.method') or line.startswith('# direct methods') or line.startswith('# virtual methods'):
                    is_mtd = True

                if line.startswith('.end method'):
                    is_mtd = False
                    if is_del:
                        is_del = False
                    else:
                        content = content + tmp + line
                        tmp = ''
                    continue

                if not is_mtd:
                    content = content + line
                else:
                    for s in android_list:
                        if s in line:
                            is_del = True
                            tmp = ''
                            break
                    if is_del:
                        tmp = ''
                    else:
                        tmp = tmp + line

    return content


def main(arg):
    if os.path.isdir(arg):
        for parent, dirnames, filenames in os.walk(arg):
            for filename in filenames:
                if filename.endswith('.smali'):
                    filepath = os.path.join(parent, filename)
                    content = process_smali(filepath)
                    with open(filepath, 'w') as f:
                        f.write(content)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='cs', description='Clear the android code of the smali')

    parser.add_argument('f', help='smali folder')
    args = parser.parse_args()
    main(args.f)
