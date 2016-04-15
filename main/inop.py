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

from libs import strtool


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='inop', description='N个字符串的匹配串')
    parser.add_argument('opcodes', metavar='N', type=str, nargs='+',
                   help='opcodes')
    args = parser.parse_args()

    opcodes = args.opcodes

    if len(opcodes) < 2:
        print("At least 2 opcodes")
        exit()

    pattern = opcodes[0]
    opcodes.remove(pattern)
    for opcode in opcodes:
        pattern = strtool.get_pattern(pattern, opcode)

    print(pattern)
