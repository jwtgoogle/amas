# Copyright 2015 LAI. All Rights Reserved.
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

from axmlparser.axml import AXML


def main(arg):
    if os.path.isdir(arg):
        rootdir = arg
        for parent, dirnames, filenames in os.walk(rootdir):
            for filename in filenames:
                filePath = os.path.join(parent, filename)
                print(filePath)

                if filePath.endswith("xml"):
                    axml = AXML(open(filePath, "rb").read())
                    axml.printAll()
                    print('\n')
                    continue

                try:
                    with zipfile.ZipFile(filePath, 'r') as z:
                        for name in z.namelist():
                            if name == "AndroidManifest.xml":
                                data = z.read(name)
                                a = AXML(data)
                                a.printAll()
                                print("\n")
                                break
                except zipfile.BadZipFile as err:
                    print(filePath, err)
    else:
        if arg.endswith("xml"):
            axml = AXML(open(arg, "rb").read())
            axml.printAll()
            # print(axml.get_xml_obj().toprettyxml())
        else:
            try:
                with zipfile.ZipFile(arg, 'r') as z:
                    for name in z.namelist():
                        if name == "AndroidManifest.xml":
                            data = z.read(name)
                            a = AXML(data)
                            a.printAll()
                            break
            except zipfile.BadZipFile as err:
                print(filePath, err)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='axmlinfos', description='获取apk的AndroidManifest信息（支持目录、文件）')
    parser.add_argument('dirName')
    args = parser.parse_args()
    main(args.dirName)
