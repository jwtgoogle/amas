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
import os.path
import io
import sys

from axmlparser.axml import AXML

DEBUG = False
MAGIC_HEADERS = {b'504b0304': 'ZIP', b'7f454c46': 'ELF'}
AXML_MAGIC_HEADER = b'03000800'
files_list = []
words = []


def displayFiles():
    files_list.sort()
    print("files:")
    for f in files_list:
        print(' ', f)
    print(" ")
    files_list.clear()


def readZip(prefix, input_zip):
    zfiledata = io.BytesIO(input_zip)
    zip_file = zipfile.ZipFile(zfiledata)
    processZipFile(zip_file, prefix)


def axmlaudit(axml):
    risk = set()

    whiteList = [
        "cn.jpush.android.service.PushReceiver",
        "cn.play.dserv.DsReceiver",
        "com.baidu.android.pushservice",
        "com.cgame.service",
        "com.ehoo.sms.receiver.BootReceiver",
        "com.lyhtgh.pay",
        "com.qihoo.psdk.local.QBootReceiver",
        "com.qihoo.gamecenter.sdk.suspend.local.QBootReceiver",
        "com.secapk.wrapper.ApplicationWrapper",
        "com.skymobi.pay",
        "com.snowfish",
        "com.tencent.StubShell",
        "com.wedo.ad",
        "com.zf.receiver.AppReceiver",
        "com.zhangzhifu.sdk.util.sms.BootReceiver"]

    # ####################### 无图标 ##########################
    if axml.getMainActivity() is None:
        risk.add("NoIcon")

    # ####################### 存在Application ########################
    flag = True
    application = axml.getApplicationName()
    if application is not None and axml.getPackageName() not in application:
        for white in whiteList:
            if white in application:
                flag = False
                break
        if flag:
            risk.add(application)

    # ####################### 存在设备管理器 ########################
    for key in sorted(axml.receivers.keys()):
        if "android.app.action.DEVICE_ADMIN_ENABLED" in axml.receivers[key]:
            risk.add("DevAdmin")
            break

    for key in sorted(axml.receivers.keys()):
        # filter white
        flag = False
        for white in whiteList:
            if white in key:
                flag = True
                break
        if flag:
            continue

        if "android.intent.action.USER_PRESENT" not in axml.receivers[key] and \
                "android.net.conn.CONNECTIVITY_CHANGE" not in axml.receivers[key] and \
                "Intent.ACTION_BOOT_COMPLETED" not in axml.receivers[key] and \
                "android.intent.action.BOOT_COMPLETED" not in axml.receivers[key]:
            continue

        flag = True
        strs = key.split('.')
        for s in strs:
            if len(s) < 3:
                continue
            else:
                for w in words:
                    if len(w) < 3:
                        continue
                    if w.lower() in s.lower():
                        flag = False
                        break
                if flag:
                    risk.add(key)
                    break
                else:
                    flag = True
        if flag is False:
            continue

        if len(strs) >= 3:
            pkg = strs[0] + "." + strs[1]
            for act in axml.activities:
                if pkg in act:
                    flag = False
                    break
            if flag:
                risk.add(key)

    # 危险权限过滤
    risk_permissions = ["android.permission.PROCESS_OUTGOING_CALLS",
                        "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
                        "com.android.browser.permission.READ_HISTORY_BOOKMARKS",
                        "com.android.browser.permission.WRITE_HISTORY_BOOKMARKS",
                        "android.permission.RECORD_AUDIO", "android.permission.RECORD_VIDEO"
                        ]
    for perm in axml.permissions:
        if perm in risk_permissions:
            risk.add(perm.replace("android.permission.", ""))

    return risk


def processZipFile(z, prefix=""):
    # 通过AndroidManifest.xml判断
    try:
        data = z.read("AndroidManifest.xml")
        a = AXML(data)
        return axmlaudit(a)
    except RuntimeError:
        pass
    except KeyError:
        pass
    # 通过子包判断

    # 通过资源文件判断
    # for name in z.namelist():
        # try:
        # data = z.read(name)
        # except RuntimeError as err:
        # print(prefix, name, err)
        # continue

        # magic_number = binascii.hexlify(data[:4])
        # if name == "AndroidManifest.xml" and magic_number == AXML_MAGIC_HEADER:
        # try:
        # a = AXML(data)
        # if prefix != "":
        # print(prefix)
        # axmlaudit(a)
        # a.printAll()
        # print('')
        # except struct.error as err:
        # print(prefix, name, err)
        # else:
        # if DEBUG:
        # print(name, data[:4], magic_number)
        # if magic_number in MAGIC_HEADERS.keys():
        # files_list.append(prefix + name + " " + MAGIC_HEADERS[magic_number])
        # if MAGIC_HEADERS[magic_number] == 'ZIP':
        # readZip(name + "/", data)


def main(dirName):
    if os.path.isdir(dirName):
        rootdir = dirName
        for parent, dirnames, filenames in os.walk(rootdir):
            for filename in filenames:
                result = False
                filePath = os.path.join(parent, filename)
                try:
                    with zipfile.ZipFile(filePath, 'r') as z:
                        result = processZipFile(z)
                        if result is not None and len(result) > 0:
                            print(filePath)
                            print(result)
                except zipfile.BadZipFile as err:
                    print(filePath, err)
    else:
        print(dirName, "folder don't exist!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='scan', description='扫描，找出存在风险的APK。')
    parser.add_argument('dirName')
    args = parser.parse_args()

    for p in sys.path:
        if "amas" in p:
            txtPath = p
            break

    with open(os.path.join(txtPath, "cfg", 'words.txt'), 'r', encoding='utf-8') as f:
        words = f.read().split()

    main(args.dirName)
