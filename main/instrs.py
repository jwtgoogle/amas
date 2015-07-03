# Copyright 2015 Google Inc. All Rights Reserved.
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

            dex = parsedex.DexFile(data)

            tmpSet = set()
            for i in range(dex.string_ids.size):
                s = dex.string(i)
                tmpSet.add(s)

            if len(inSet) is 0:
                inSet = tmpSet
            else:
                inSet = inSet.intersection(tmpSet)

    for s in inSet:
        if isinstance(s, int) or isinstance(s, str):
            print(type(s), s)
            continue
        h = binascii.b2a_hex(s)
        try:
            print('<!-- ', end='')
            print(s.decode(errors='ignore'), end='')
            print('-->', end='')
            print("`", end='')
            print(
                '''<stdmethod alias="D_FindString" string_mode="IMME"  clsid="{4F871BAF-90CC-41b3-B90E-D0D666DFF84C}">''', end='')
            print(h.upper().decode(errors='ignore'), end='')
            print('''</stdmethod>''')
        except UnicodeEncodeError as e:
            print(e)
            continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='instrs', description='取目录下APK文件的字符串交集')
    parser.add_argument('dirName')
    args = parser.parse_args()
    main(args.dirName)
