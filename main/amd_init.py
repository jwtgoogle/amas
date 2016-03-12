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
import sys
import os

from amd.util import FeatureTool

'''
初始化训练数据

1、支持单个分类初始化，支持多个分类初始化，自动初始化到data目录
2、初步考虑的特征为：权限、action、接收器数量、服务数量、act数量、是否有图标、是否有application、证书名长度


这种情况会具有通用性，具有类似功能，但是，不同的类别的样本，也会分到这里去。包括一些白样本，所以，这里仅仅作为参考。
——这也是我的目的，即便不是属于这一类如果能找到类似的也不错了。

dex，字符串多少、有效子包、包名
'''

MAGIC_HEADERS = {b'504b0304': 'ZIP', b'7f454c46': 'ELF'}
AXML_MAGIC_HEADER = b'03000800'
cfgDir = ""
data_dir = ""


def main(arg):
    if os.path.isdir(arg):
        rootdir = arg
        print("Begin to init raw data.")

        for parent, dirnames, filenames in os.walk(rootdir):
            for dirname in dirnames:
                f = data_dir + dirname
                if(os.path.exists(f)):
                    os.remove(f)

            if len(dirnames) == 0:
                f = data_dir + parent
                if(os.path.exists(f)):
                    os.remove(f)

            for filename in filenames:
                if '.' in filename:
                    continue

                label = parent.split(os.sep)[-1]
                filepath = os.path.join(parent, filename)

                featureTool = FeatureTool(filepath)
                feature_str = featureTool.get_feature_str()
                with open(data_dir + label, 'a+') as f:
                    if feature_str is None:
                        print(filepath, 'is None!')
                        continue
                    f.write(filename + ',' + feature_str + ',' + label + '\n')

        print("Finish.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='init', description='初始化训练数据')
    parser.add_argument('dirName')
    args = parser.parse_args()

    for p in sys.path:
        if "amas" in p:
            cfgDir = p + os.sep + "cfg" + os.sep
            data_dir = p + os.sep + "data" + os.sep
            break

    main(args.dirName)
