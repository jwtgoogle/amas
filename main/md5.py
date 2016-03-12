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


def get_md5(filepath):
    md5 = hashlib.md5()
    f = io.FileIO(filepath, 'r')
    bytes = f.read(1024)
    while(bytes != b''):
        md5.update(bytes)
        bytes = f.read(1024)
    f.close()
    md = md5.hexdigest()

    return md


def main(arg):
    if os.path.isfile(arg):
        print(get_md5(arg))
        return

    if os.path.isdir(arg):
        for parent, dirnames, filenames in os.walk(arg):
            for filename in filenames:
                filepath = os.path.join(parent, filename)
                lenght = len(filepath)
                print(filepath, (50 - lenght) * ' ', get_md5(filepath))

        return

    print("")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='md5', description='get md5')
    parser.add_argument('f', help='filename or dirname')
    args = parser.parse_args()
    main(args.f)
