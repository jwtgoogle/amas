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

import zipfile
import argparse
import os
import os.path
import binascii
import sys

from enjarify import parsedex


def main(arg):
    rootdir = arg
    inSet = {}
    for parent, dirnames, filenames in os.walk(rootdir):
        for filename in filenames:
            flag = 0
            filePath = os.path.join(parent, filename)

            try:
                with zipfile.ZipFile(filePath, 'r') as z:
                    for name in z.namelist():
                        if name == "classes.dex":
                            data = z.read(name)
                            flag = 1
                            break
            except zipfile.BadZipFile as err:
                print(filePath, err)
            if flag is not 1:
                continue

            try:
                dex = parsedex.DexFile(data)
            except Exception as e:
                # raise
                print(filePath, "'s dex can not be parsed, please report to the author.")
                continue

            tmpSet = set()
            for i in range(dex.string_ids.size):
                s = dex.string(i)
                tmpSet.add(s)

            if len(inSet) is 0:
                inSet = tmpSet
            else:
                inSet = inSet.intersection(tmpSet)

    apis = ""
    with open(os.path.join(sys.path[1], "cfg", 'api-versions.xml'), 'r', encoding='utf-8') as f:
        apis = f.read()

    strs = ""
    with open(os.path.join(sys.path[1], "cfg", 'strs.txt'), 'r', encoding='utf-8') as f:
        strs = f.read()

    apis = apis + strs
    # print(apis)
    # exit()

    for s in inSet:
        if isinstance(s, int) or isinstance(s, str):
            # print(type(s), s)
            continue

        if len(s) < 4:
            continue

        s_decode = s.decode(errors='ignore')
        if s_decode in apis:
            continue
        if s_decode.startswith("L") and s_decode.endswith(";"):
            continue

        # if "access$" in s_decode or "<" in s_decode :
        #     continue

        print(s_decode)

        continue

        h = binascii.b2a_hex(s)
        try:
            print('<!-- ', end='')
            print(s_decode, end=' ')
            print('-->', end='')
            print("", end='')
            # TODO 这里需要考虑那些公共类、公共字符串，可以排除在外

            print(
                '''<stdmethod alias="D_FindString" string_mode="IMME"  clsid="{4F871BAF-90CC-41b3-B90E-D0D666DFF84C}">''', end='')
            print(h.upper().decode(errors='ignore'), end='')
            print('''</stdmethod>''')
        except UnicodeEncodeError as e:
            print(e)
            continue

# TODO 后续考虑完成清单信息

if __name__ == "__main__":
    # 使用这个脚本之前，最好将非恶意代码都去掉
    # 找出多个dex中的共同点
    parser = argparse.ArgumentParser(
        prog='instrs', description='提取公共字符串。（清单信息、文件——待完成）')
    parser.add_argument('dirName')
    args = parser.parse_args()
    main(args.dirName)
