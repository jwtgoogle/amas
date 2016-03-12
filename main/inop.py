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

DEBUG = False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='inop', description='取2个opcode串的交集。')
    parser.add_argument('opcode1')
    parser.add_argument('opcode2')
    args = parser.parse_args()

    if DEBUG:
        print(args.opcode1)
        print(args.opcode2)

    opcode1 = args.opcode1
    opcode1_len = len(opcode1)
    opcode2 = args.opcode2
    opcode2_len = len(opcode2)

    opcode_seq = []

    i = 2
    opcode1_rindex = opcode1_len  # opcode1 最右边开始截取的位置
    opcode2_rindex = opcode2_len  # opcode2 可以匹配到的最右边的位置
    match_index = opcode2_len     # 命中的位置，如果为-1，则说明没有命中，需要重新开始匹配
    opcode2_last_rindex = 0       # 最后一次命中的最右边索引
    while opcode1_rindex >= i:
        '''
            1、第一次开始从右边开始取OPCODE，不断地组合，找其在第二个OPCODE序列中位置。

            2、第二次，及其之后，则从之前没有命中的位置重新开始，去匹配OPCODE2剩下的。（仅仅单个命中，或者没有命中，都忽略。）

        '''
        sub = opcode1[opcode1_rindex - i: opcode1_rindex]
        if DEBUG:
            print("sub : ", sub)
        match_index = opcode2[:opcode2_rindex].rfind(sub)

        if match_index < 0:
            '''
                没有命中，则将之前命中的串记录下来。
                之后，重新开始匹配
            '''
            opcode1_rindex = opcode1_rindex - i + 2
            if DEBUG:
                print("opcode1_rindex", opcode1_rindex)
            if len(sub) == 2:
                opcode1_rindex = opcode1_rindex - 2
            opcode2_rindex = opcode2_rindex - i + 2
            i = 2
            if len(sub[2:]) > 0:
                opcode_seq.append(sub[2:])
            continue
        elif match_index == 0:
            opcode_seq.append(sub)
            break

        i = i + 2
        if DEBUG:
            print("opcode1_rindex", opcode1_rindex, i)
            print(match_index)

    for op in opcode_seq[::-1]:
        print(op, end="*")
    print()
