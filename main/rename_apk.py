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
import zipfile
import hashlib
import io


def main(rootdir):
    if not os.path.isdir(rootdir):
        print(rootdir, 'is not a directory.')
        return

    for parent, dirnames, filenames in os.walk(rootdir):
        for filename in filenames:
            print(filename)
            filepath = os.path.join(parent, filename)

            with zipfile.ZipFile(filepath, 'r') as myzip:
                info = myzip.getinfo("AndroidManifest.xml")     # FIXME 某些文件不存在 classes.dex 文件

            year = str(info.date_time[0])
            m = str(info.date_time[1])
            month = len(m) != 1 and m or str(0) + m
            d = str(info.date_time[2])
            day = len(d) != 1 and d or str(0) + d

            # h = str(info.date_time[3])
            # m = str(info.date_time[4])
            # s = str(info.date_time[5])

            sha = hashlib.sha256()
            # sha = hashlib.md5()
            f = io.FileIO(filepath, 'r')
            bytes = f.read(1024)
            while(bytes != b''):
                sha.update(bytes)
                bytes = f.read(1024)
            f.close()

            sha256 = sha.hexdigest()

            newfilepath = os.path.join(parent, year + month + day + '-' + sha256)
            shutil.move(filepath, newfilepath)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='ra', description='rename apk to Time-SHA256')
    parser.add_argument('dirName')
    args = parser.parse_args()
    main(args.dirName)
