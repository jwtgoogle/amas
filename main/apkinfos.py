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


def print_infos(z):
    name = "AndroidManifest.xml"
    if "AndroidManifest.xml" in z.namelist():
        data = z.read(name)
        axml = AXML(data)
        axml.printAll()

    for name in z.namelist():
        data = z.read(name)
        magic_number = binascii.hexlify(data[:4])
        if magic_number in MAGIC_HEADERS.keys():
            print(name, MAGIC_HEADERS[magic_number])
            if MAGIC_HEADERS[magic_number] == "ZIP":
                files_list.append(name)

    print("\n")


def print_sub_zips(z):
    for name in files_list:
        print(">>>", name)
        data = z.read(name)
        zfiledata = io.BytesIO(data)
        zip_file = zipfile.ZipFile(zfiledata)
        print_infos(zip_file)


def main(arg):
    if os.path.isdir(arg):
        rootdir = arg
        for parent, dirnames, filenames in os.walk(rootdir):
            for filename in filenames:
                filePath = os.path.join(parent, filename)
                print(filePath)
                if zipfile.is_zipfile(filePath):
                    try:
                        with zipfile.ZipFile(filePath, mode="r") as z:
                            print_infos(z)
                            if len(files_list) > 0:
                                print_sub_zips(z)
                                files_list.clear()
                    except zipfile.BadZipFile as z:
                        print(filePath, e)
    elif os.path.isfile(arg):
        if zipfile.is_zipfile(arg):
            try:
                with zipfile.ZipFile(arg, mode="r") as z:
                    print_infos(z)
                    if len(files_list) > 0:
                        print_sub_zips(z)
                        files_list.clear()
            except zipfile.BadZipFile as z:
                print(filePath, e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='apkinfos', description='get apk infos')
    parser.add_argument('filename')
    args = parser.parse_args()
    main(args.filename)
