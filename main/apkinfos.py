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
import io

from axmlparser.axml import AXML

DEBUG = False
MAGIC_HEADERS = {b'504b0304': 'ZIP', b'7f454c46': 'ELF'}
AXML_MAGIC_HEADERS = [b'03000800', b'00000800']
files_list = []


def displayFiles():
    files_list.sort()
    print("files:")
    for f in files_list:
        print(' ', f)
    print(" ")
    files_list.clear()


def readZip(prefix, input_zip):
    zfiledata = io.BytesIO(input_zip)
    zip_file = zipfile.ZipFile(zfiledata)
    processZipFile(zip_file, prefix)


def processZipFile(z, prefix=""):
    for name in z.namelist():
        try:
            data = z.read(name)
        except RuntimeError as err:
            print(prefix, name, err)
            continue

        magic_number = binascii.hexlify(data[:4])

        if name == "AndroidManifest.xml" and magic_number in AXML_MAGIC_HEADERS:
            # try:
            a = AXML(data)
            if prefix != "":
                print(prefix)
            a.printAll()
            print('')
            # except struct.error as err:
            #     print(prefix, name, err)
        else:
            if DEBUG:
                print(name, data[:4], magic_number)
            if magic_number in MAGIC_HEADERS.keys():
                files_list.append(prefix + name + " " +
                                  MAGIC_HEADERS[magic_number])
                if MAGIC_HEADERS[magic_number] == 'ZIP':
                    readZip(name + "/", data)


def main(arg):
    if os.path.isdir(arg):
        rootdir = arg
        for parent, dirnames, filenames in os.walk(rootdir):
            for filename in filenames:
                filePath = os.path.join(parent, filename)
                print(filePath)

                try:
                    with zipfile.ZipFile(filePath, 'r') as z:
                        processZipFile(z)
                        # displayFiles()
                except zipfile.BadZipFile as err:
                    print(filePath, err)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='axmlinfos', description='获取APK的整体信息，包含清单、文件。')
    parser.add_argument('dirName')
    args = parser.parse_args()
    main(args.dirName)
