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

import sys
import os
import argparse
import pickle

from amd.util import FeatureTool


def main(rootdir):
    if not os.path.isdir(rootdir):
        print(rootdir, 'is not a directory.')
        return

    # 加载已知模型
    pwd = sys.path[1]
    data_pkl = pwd + os.sep + "cfg" + os.sep + 'data.pkl'
    clf = pickle.load(open(data_pkl, 'rb'))

    # 加载labels
    labels = []
    labels_path = pwd + os.sep + "cfg" + os.sep + 'labels'
    with open(labels_path, 'r') as f:
        while 1:
            lines = f.readlines(10000)
            if not lines:
                break
            for line in lines:
                if len(line) < 2:
                    continue
                labels.append(line.replace('\n', ''))

    for parent, dirnames, filenames in os.walk(rootdir):
        for filename in filenames:
            filepath = os.path.join(parent, filename)
            featureTool = FeatureTool(filepath)
            if featureTool.get_feature_str is None:
                print(filepath, "is None.")
                continue
            index = clf.predict(featureTool.get_feature())
            print(filepath, ' : ', labels[int(index)])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='instrs', description='预测')
    parser.add_argument('dirName')
    args = parser.parse_args()
    main(args.dirName)
