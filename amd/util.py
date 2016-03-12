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
import os.path
import sys
import os
import subprocess
import binascii

from axmlparser.axml import AXML
from enjarify import parsedex


AXML_MAGIC_HEADER = b'03000800'
ELF_MAGIC_HEADER = b'7f454c46'


class FeatureTool:
    '''
        获取APK的特征
    '''

    def __init__(self, apk):
        # 初始化配置目录
        self.pwd = sys.path[1]
        self.__varify_dirs()
        self.cfg_dir = self.pwd + os.sep + "cfg" + os.sep

        self.feature_str = None
        self.feature = None

        self.axml_str = None
        self.files_str = '0'
        self.dex_str = '0'

        self.__parse(apk)

    def __varify_dirs(self):
        if 'amas' not in self.pwd:
            for p in sys.path:
                if "amas" in p:
                    self.pwd = p
                    break

    def get_feature(self):
        return self.feature

    def get_feature_str(self):
        return self.feature_str

    def get_dex_str(self):
        return self.dex_str

    def __parse(self, file_parth):
        output = \
            subprocess.check_output(
                ["keytool", "-printcert", "-jarfile", file_parth])
        sign_len = len(output.decode(
            'gbk', 'ignore').split('\n')[4].split(': ')[1])

        try:
            with zipfile.ZipFile(file_parth, 'r') as z:
                self.__process_apk(z)
                self.feature_str = self.axml_str + ',' + \
                    str(sign_len) + ',' + self.files_str
                tokens = self.feature_str.strip().split(',')
                self.feature = [[float(tk) for tk in tokens]]
        except zipfile.BadZipFile:
            return None

    def __process_apk(self, z, prefix=""):
        # 'assets/' 'res/' 目录下 elf 文件的数量
        elf_size = 0

        for name in z.namelist():
            try:
                data = z.read(name)
            except RuntimeError as err:
                print(prefix, name, err)
                continue

            magic_number = binascii.hexlify(data[:4])

            if ELF_MAGIC_HEADER == magic_number:
                if name.startswith('assets/') and \
                        not name.endswith(".so") or name.startswith('res/'):
                    elf_size = elf_size + 1
                    continue

            if name == "AndroidManifest.xml" and magic_number == AXML_MAGIC_HEADER:
                a = AXML(data)
                self.__process_axml(a)
                continue

            # FIXME 加上这些数据后，效果很不好，还不如清单！
            if name == "classes.dex":
                try:
                    dex = parsedex.DexFile(data)
                    # dex类数量
                    self.dex_str = str(dex.class_defs.size)
                except Exception:
                    print(z, "'s dex can not be parsed, please report to the author.")
                    continue

        self.files_str = str(elf_size)

    def __process_axml(self, axml):
        '''
            权限、action、接收器数量、服务数量、act数量、是否有图标、是否有application
        '''
        # read permissions.txt
        v = 0x1
        permDict = {}
        with open(self.cfg_dir + "permissions.txt") as f:
            lines = f.readlines()
            for line in lines:
                permDict[line.replace('\n', '')] = v
                v = v << 1

        permV = 0
        for perm in axml.permissions:
            for key in permDict.keys():
                if key in perm:
                    permV = permV + permDict.get(key)
        permV = str(permV)

        # read actions.txt
        v = 0x1
        actionDict = {}
        with open(self.cfg_dir + "actions.txt") as f:
            lines = f.readlines()
            for line in lines:
                actionDict[line.replace('\n', '')] = v
                v = v << 1

        actionV = 0
        for rev in sorted(axml.receivers.keys()):
            for ac in axml.receivers[rev]:
                if ac in actionDict.keys():
                    actionV = actionV + actionDict.get(ac)
        actionV = str(actionV)

        hasIcon = "0"
        hasApp = "0"
        if axml.getMainActivity():
            hasIcon = "1"

        if axml.getApplicationName():
            hasApp = "1"

        revsNum = str(len(axml.receivers))
        servsNum = str(len(axml.services))
        actsNum = str(len(axml.activities))

        self.axml_str = permV + ',' + actionV + ',' + revsNum + ',' + servsNum + \
            ',' + actsNum + ',' + hasIcon + ',' + hasApp
