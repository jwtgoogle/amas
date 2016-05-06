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

import zipfile
import argparse
import os
import os.path
import binascii
import io
import shutil

from libs.axmlparser.axml import AXML
from libs.enjarify import parsedex


def chkp(filepath):
    if zipfile.is_zipfile(filepath):
        flag = False
        no_main = True

        try:
            with zipfile.ZipFile(filepath, mode="r") as z:
                z.testzip()
                data = z.read("AndroidManifest.xml")

                axml = AXML(data)
                package = axml.getPackageName().replace('.', '/')
                application = axml.getApplicationName()

                if application is None:
                    return ('nopacked', '', '')

                application = axml.getApplicationName().replace('.', '/')

                if application.startswith('/'):
                    application = package + application

                main_activity = axml.getMainActivity()
                if main_activity:
                    main_activity = main_activity.replace('.', '/')

                dexs = []
                for name in z.namelist():
                    if name.startswith("classes") and name.endswith(".dex"):
                        dexs.append(z.read(name))

                if len(dexs) == 0:
                    return ('nopacked', 'no classes.dex', '')

                for dat in dexs:
                    if flag:
                        break
                    dexFile = parsedex.DexFile(dat)
                    for dexClass in dexFile.classes:
                        if flag and no_main:
                            break
                        if dexClass.name.decode() == application:
                            dexClass.parseData()
                            for method in dexClass.data.methods:
                                if method.id.name.decode() == "attachBaseContext":
                                    flag = True

                        if main_activity and dexClass.name.decode() == main_activity:
                            no_main = False

        except zipfile.BadZipfile as e:
            return ('unknown', 'Errors.', e)

        if flag or no_main:
            return ("packed.", application, main_activity)
        else:
            return ("nopacked.", application, main_activity)
    else:
        return ('unknown', 'Errors.', 'not a zipfile')


def main(args):
    if os.path.isdir(args.dirname):
        rootdir = args.dirname
        if  args.m:
            if not os.path.exists('nopacked'):
                os.mkdir('nopacked')
            if not os.path.exists('packed'):
                os.mkdir('packed')

        for parent, dirnames, filenames in os.walk(rootdir):
            for filename in filenames:
                filepath = os.path.join(parent, filename)
                result = chkp(filepath)

                if args.m:
                    dst = result[0] + os.sep + filename
                    if dst not in filepath:
                        shutil.move(filepath, dst)

                    if args.v:
                        print(filepath, result[0], result[1], result[2])
                else:
                    print(filepath, result[0], result[1], result[2])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='chkp', description='check APKs whether have been packed')
    parser.add_argument('dirname')
    parser.add_argument('-m', action='store_true', help='move', required=False)
    parser.add_argument('-v', action='store_true', help='verbose', required=False)
    args = parser.parse_args()
    main(args)
