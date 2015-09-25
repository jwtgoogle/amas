# Copyright 2015 LAI. All Rights Reserved.
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
import binascii
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
    print("-" * 10 + " audit " + "-" * 10)
    if axml.getMainActivity is None:
        print("Activity : No Icon\n")

    application = axml.getApplicationName()
    if application is not None and axml.getPackageName() not in application:
        print("Application : " + application + "\n")

    # Receivers
    riskReceivers = []
    whiteList = ["com.skymobi.pay.sdk", "com.snowfish"]
    isFirst = True
    for key in sorted(axml.receivers.keys()):
        # filter white
        flag = False
        for white in whiteList:
            if white in key:
                flag = True
                break
        if flag:
            break

        if "android.app.action.DEVICE_ADMIN_ENABLED" in axml.receivers[key]:
            riskReceivers.append(key + " : DEVICE_ADMIN_ENABLED")
        if "android.intent.action.PACKAGE_ADDED" in axml.receivers[key]:
            riskReceivers.append(key + " : PACKAGE_ADDED")
        if "android.intent.action.USER_PRESENT" not in axml.receivers[key] and \
                "android.net.conn.CONNECTIVITY_CHANGE" not in axml.receivers[key] and \
                "Intent.ACTION_BOOT_COMPLETED" not in axml.receivers[key] and \
                "android.intent.action.BOOT_COMPLETED" not in axml.receivers[key]:
            continue

        flag = True
        strs = key.split('.')
        for s in strs:
            if len(s) < 3:
                # print("Risk len : " + s + ":" + key + str(axml.receivers[key]))
                # break
                continue
            else:
                for w in words:
                    if len(w) < 3:
                        continue
                    if w.lower() in s.lower():
                        flag = False
                        break
                if flag:
                    riskReceivers.append(key + " : Dynamic Loading")
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
                riskReceivers.append(key + " : Dynamic Loading")
    isFirst = True
    for r in riskReceivers:
        if isFirst:
            print("Receivers:")
            isFirst = False
        print(r)
    if isFirst is False:
        print()

    # DANGEROUS PERMISSION
    isFirst = True
    risk_permissions = ["android.permission.CALL_PHONE", "android.permission.SEND_SMS",
                        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
                        "android.permission.WRITE_SMS", "android.permission.PROCESS_OUTGOING_CALLS",
                        "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
                        "com.android.browser.permission.READ_HISTORY_BOOKMARKS",
                        "com.android.browser.permission.WRITE_HISTORY_BOOKMARKS",
                        "android.permission.RECORD_AUDIO", "android.permission.RECORD_VIDEO",
                        "android.permission.WRITE_APN_SETTINGS"
                        ]
    for perm in axml.permissions:
        if perm in risk_permissions:
            if isFirst:
                print("Permissions:")
                isFirst = False
            print(perm)

    print("-" * 30)

    axml.printAll()


def processZipFile(z, prefix=""):
    for name in z.namelist():
        try:
            data = z.read(name)
        except RuntimeError as err:
            print(prefix, name, err)
            continue

        magic_number = binascii.hexlify(data[:4])
        if name == "AndroidManifest.xml" and magic_number == AXML_MAGIC_HEADER:
            # try:
            a = AXML(data)
            if prefix != "":
                print(prefix)
            axmlaudit(a)
            # a.printAll()
            print('')
            # except struct.error as err:
            #     print(prefix, name, err)
        else:
            if DEBUG:
                print(name, data[:4], magic_number)
            if magic_number in MAGIC_HEADERS.keys():
                files_list.append(prefix + name + " " + MAGIC_HEADERS[magic_number])
                if MAGIC_HEADERS[magic_number] == 'ZIP':
                    readZip(name + "/", data)


def main(arg):
    if os.path.isdir(arg):
        rootdir = arg
        for parent, dirnames, filenames in os.walk(rootdir):
            for filename in filenames:
                filePath = os.path.join(parent, filename)
                print(filePath)

                if filePath.endswith("xml"):
                    axml = AXML(open(filePath, "rb").read())
                    axmlaudit(axml)
                    # axml.printAll()
                    print('\n')
                    continue

                try:
                    with zipfile.ZipFile(filePath, 'r') as z:
                        processZipFile(z)
                        displayFiles()
                except zipfile.BadZipFile as err:
                    print(filePath, err)

    else:
        if arg.endswith("xml"):
            axml = AXML(open(arg, "rb").read())
            axml.printAll()
            # print(axml.get_xml_obj().toprettyxml())
        else:
            try:
                with zipfile.ZipFile(arg, 'r') as z:
                    processZipFile(z)
            except zipfile.BadZipFile as err:
                print(filePath, err)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='axmlinfos', description='获取apk信息（支持目录、文件）')
    parser.add_argument('dirName')
    args = parser.parse_args()

    for p in sys.path:
        if "amas" in p:
            txtPath = p
            break

    with open(os.path.join(txtPath, "main", 'words.txt'), 'r', encoding='utf-8') as f:
        words = f.read().split()

    main(args.dirName)
