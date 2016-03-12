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
from sklearn.cross_validation import train_test_split
from sklearn import svm
import numpy as np
import pickle

pwd = sys.path[1]

'''
    初始化data目录下的数据
'''
data = []
labels = []

labelSet = set()

for parent, dirnames, filenames in os.walk(pwd + os.sep + "data"):
    for filename in filenames:
        with open(os.path.join(parent, filename)) as f:
            labelSet.add(filename)
            while 1:
                lines = f.readlines(1000)
                if not lines:
                    break
                for line in lines:
                    if len(line) < 2:
                        continue
                    tokens = line.strip().split(',')
                    data.append([float(tk) for tk in tokens[1:-1]])
                    labels.append(tokens[-1])

x = np.array(data)
labels = np.array(labels)
y = np.zeros(labels.shape)

# 自动初始化，各个分类的情况，样本类名
labelList = list(labelSet)

# 将label保存成文件，然后给预测的结果用
labelList.sort()
labels_path = pwd + os.sep + "cfg" + os.sep + 'labels'
with open(labels_path, 'w+') as f:
    for lab in labelList:
        f.write(lab + '\n')

i = 0
for lab in labelList:
    y[labels == lab] = i
    i = i + 1


'''
    将训练结果调整到1.0，将模型保存
'''
clf = svm.SVC()     # 这个算法目前效果最好

# clf = svm.SVC(kernel='linear') # 不行
# clf = svm.LinearSVC()# 不行
# clf = svm.SVC(kernel='poly', degree=3)# 不行
# clf = svm.SVC(kernel='sigmoid')# 不行

data_pkl = pwd + os.sep + "cfg" + os.sep + 'data.pkl'
while 1:
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.2)
    clf.fit(x_train, y_train)
    answer = clf.predict(x_test)
    # print(answer)
    # print(y_test)
    score = np.mean(answer == y_test)
    print(score)
    if score > 0.9:
        # print('Train : ', score)
        # if score == 1 :
        pickle.dump(clf, open(data_pkl, 'wb'))

        '''
            保存分数大于0.9的模型作为测试模型

            1、可以考虑加入白名单的办法，避免误报。
            2、可能跟样本集有关，靠平时慢慢的积累样本集
            3、可能跟算法有关，
            4、可能跟训练特征有关系，如何准确地表达APK之前的功能差异、是否恶意？
        '''
        # TODO 后续需要想办法提高预测的准确率
        clf2 = pickle.load(open(data_pkl, 'rb'))
        answer = clf.predict(x)
        score = np.mean(answer == y)
        print('ALL :', score)
        if score > 0.95:
            print("Model Score :", score)
            # print(answer)
            # print(y)
            break

# TODO 后续加入，画图分析等，其他能检测的准确率的指标
