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


import zipfile
import argparse
import os
import os.path
import binascii
import sys

from enjarify import parsedex
from axmlparser.axml import AXML


MAGIC_HEADERS = {b'504b0304': 'ZIP', b'7f454c46': 'ELF'}
AXML_MAGIC_HEADERS = [b'03000800', b'00000800']
DEX_MAGIC_HEADERS = [b'6465780a']

is_first = True

DEBUG = False

pkgd = {}
inpackage = set()
permd = {}
inperms = set()
actiond = {}
inacts = set()

activitiesd = {}
inacivities = set()
recd = {}
inrecs = set()
servd = {}
inservs = set()

activities = []
receivers = []
services = []

min_a = 99
max_a = 0
min_r = 99
max_r = 0
min_s = 99
max_s = 0
min_p = 99
max_p = 0

inSet = {}


def process_axml(data):
    global is_first
    global inpackage
    global inperms
    global inacts
    global inacivities
    global inrecs
    global inservs

    global pkgd
    global permd
    global recd
    global servd
    global actiond
    global activitiesd

    global activities
    global receivers
    global services

    global min_a
    global min_r
    global min_s
    global min_p
    global max_a
    global max_r
    global max_s
    global max_p

    a = AXML(data)

    p_set = set()
    pkg = a.getPackageName()
    p_set.add(pkg)
    if pkg not in pkgd.keys():
        pkgd[pkg] = 1
    else:
        pkgd[pkg] = pkgd[pkg] + 1

    a_set = set()
    tmp = a.getActivities()

    if len(tmp) < min_a:
        min_a = len(tmp)
    if len(tmp) > max_a:
        max_a = len(tmp)

    tmp_list = []
    for act in a.getActivities():
        # 截取掉包名 AttrMatch 不支持包名
        a_set.add(act)
        tmp_list.append(act.replace(pkg, ''))
        if act in activitiesd.keys():
            activitiesd[act] = activitiesd[act] + 1
        else:
            activitiesd[act] = 1

        key = act.split('.')[-1]
        a_set.add(key)
        if key in activitiesd.keys():
            activitiesd[key] = activitiesd[key] + 1
        else:
            activitiesd[key] = 1

    activities.append(tmp_list)

    r_set = set()
    tmp = a.getReceivers()
    if len(tmp) < min_r:
        min_r = len(tmp)
    if len(tmp) > max_r:
        max_r = len(tmp)

    tmp_list = []
    for r in a.getReceivers():
        r_set.add(r)
        tmp_list.append(r.replace(pkg, ''))
        if r not in recd.keys():
            recd[r] = 1
        else:
            recd[r] = recd[r] + 1

        key = r.split('.')[-1]
        r_set.add(key)
        if key not in recd.keys():
            recd[key] = 1
        else:
            recd[key] = recd[key] + 1

    receivers.append(tmp_list)

    s_set = set()
    tmp = a.getServices()
    if len(tmp) < min_s:
        min_s = len(tmp)
    if len(tmp) > max_s:
        max_s = len(tmp)

    tmp_list = []
    for s in a.getServices():
        s_set.add(s)
        tmp_list.append(s.replace(pkg, ''))
        if s not in servd.keys():
            servd[s] = 1
        else:
            servd[s] = servd[s] + 1

        key = s.split('.')[-1]
        s_set.add(key)
        if key not in servd.keys():
            servd[key] = 1
        else:
            servd[key] = servd[key] + 1

    services.append(tmp_list)

    permissions = a.getPermissions()
    tmp_p = set()
    for p in permissions:
        # 1、 仅计算 android.permission
        if 'android.permission' in p:
            tmp_p.add(p)
    perm_num = len(tmp_p)

    '''
    WRITE_EXTERNAL_STORAGE & READ_PHONE_STATE:

    If both your minSdkVersion and targetSdkVersion values are set to 3 or lower,
    the system implicitly grants your app this permission.
    If you don't need this permission, be sure your targetSdkVersion is 4 or higher.
    '''
    if int(a.getMinSdkVersion()) <= 3 and int(a.getTargetSdkVersion()) <= 3:
        if "android.permission.WRITE_EXTERNAL_STORAGE" not in tmp_p:
            perm_num = perm_num + 1
        if "android.permission.READ_PHONE_STATE" not in tmp_p:
            perm_num = perm_num + 1

    if perm_num < min_p:
        min_p = perm_num
    if perm_num > max_p:
        max_p = perm_num
    for key in permissions:
        if key not in permd.keys():
            permd[key] = 1
        else:
            permd[key] = permd[key] + 1

    actions = a.getActions()
    for key in actions:
        if key not in actiond.keys():
            actiond[key] = 1
        else:
            actiond[key] = actiond[key] + 1

    if is_first:
        is_first = False
        inpackage = p_set
        inperms = a.getPermissions()
        inacts = a.getActions()
        inacivities = a_set
        inrecs = r_set
        inservs = s_set
    else:
        inpackage = inpackage & p_set
        inperms = inperms & a.getPermissions()
        inacts = inacts & a.getActions()
        inacivities = inacivities & a_set
        inrecs = inrecs & r_set
        inservs = inservs & s_set


def process_apk(file_path, name):
    if DEBUG:
        print(file_path)
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            z.testzip()
            if name in z.namelist():
                try:
                    data = z.read(name)
                except RuntimeError as err:
                    print(file_path, err)
                magic_number = binascii.hexlify(data[:4])

                if magic_number in AXML_MAGIC_HEADERS:
                    process_axml(data)
                elif magic_number in DEX_MAGIC_HEADERS:
                    process_dex(data)
                else:
                    print("Error magic number : ", file_path, magic_number)
    except zipfile.BadZipFile as err:
        print(file_path, err)
        return -1

    return 0


def match_pkgs(strs):
    # for s in strs:
    #     print(s)

    tmp = strs[0]
    # print("\n" + tmp)
    for i in range(0, len(tmp)):
        for s in strs:
            if tmp[:i] not in s:
                if i < 3:
                    return None
                return tmp[:i - 1] + '*'

    for i in range(0, len(tmp)):
        # print(tmp[len(tmp) - i - 1:])
        for p in strs:
            if tmp[len(tmp) - i:] not in p:
                if i < 3:
                    return None
                return '*' + tmp[len(tmp) - i - 1:]

    return None


def match_a_r_s(lists):

    # for item in lists:
    #     print(item)

    matchs = []

    # 某个集合为空的情况，意味着某个样本没有对应的节点，故不做交集
    for l in lists:
        if len(l) == 0:
            return matchs

    # 自前往后匹配
    pkg_acts = lists[0]
    for act in pkg_acts:
        if act.startswith('.'):
            continue

        flag = False
        for m in matchs:
            if m.replace('*', '') in act:
                flag = True
                break

        if flag and len(matchs) > 0:
            continue

        # print(act)
        for i in range(1, len(act)):
            # print('->', act[:i])
            flag = False
            for item in lists:
                # 必须在所有的 acitivity 里面都包含
                has = False
                for other_act in item:
                    if other_act.startswith(act[:i]):
                        # print(act[:i], other_act)
                        has = True
                        break

                if not has:
                    # 不包含的情况，则需要终止
                    # print(act[:i])
                    if i > 3 and act[:i - 1]:
                        matchs.append(act[:i - 1] + '*')
                    flag = True
                    break
            if flag:
                break

    # 自后往前匹配
    for act in pkg_acts:
        flag = False
        for m in matchs:
            if m.replace('*', '') in act:
                flag = True
                break

        if flag and len(matchs) > 0:
            continue

        for i in range(0, len(act)):
            # print(act[len(act) - i - 1:])
            flag = True
            for item in lists:
                # 必须在所有的 acitivity 里面都包含
                has = False
                for other_act in item:
                    # print(other_act)
                    if other_act.endswith(act[len(act) - i - 1:]):
                        has = True
                        break
                if not has:
                    # 不包含的情况，则需要终止
                    flag = False
                    break
            if not flag:
                if i > 2:
                    matchs.append('*' + act[len(act) - i:])
                break

    tmp = set()
    for m1 in matchs:
        for m2 in matchs:
            new = m1.replace('*', '')
            if m1 != m2 and new in m2:
                tmp.add(m1)

    for m in tmp:
        matchs.remove(m)

    return matchs


def in_am(rootdir, is_statistics):
    sum = 0
    am_name = "AndroidManifest.xml"

    # FIXME 需要考虑没有清单的情况
    for parent, dirnames, filenames in os.walk(rootdir):
        for filename in filenames:
            sum = sum + 1
            filePath = os.path.join(parent, filename)
            result = process_apk(filePath, am_name)
            sum = sum + result

    flag = False
    match_pkg = None
    if len(inpackage) == 1:
        print(inpackage.pop())
        flag = True
    else:
        pkgs = []
        for item in pkgd.items():
            pkgs.append(item[0])

        match_pkg = match_pkgs(pkgs)
        if match_pkg:
            print(match_pkg)
            flag = True
    if flag:
        print()
        flag = False

    tmp = list(inperms)
    tmp.sort()
    for p in tmp:
        flag = True
        if 'android.permission.' in p or 'com.android.launcher.permission' in p:
            print(p)
    if flag:
        print()
        flag = False

    tmp = list(inacts)
    tmp.sort()
    for p in tmp:
        flag = True
        print(p)
    if flag:
        print()
        flag = False

    tmp = list(inacivities)
    tmp.sort()
    i = 0
    for p in tmp:
        if '.' in p:
            i = i + 1
            if i > 5:
                break
            flag = True
            print(p)
    if flag:
        print()
        flag = False

    matchs = match_a_r_s(activities)
    for m in matchs:
        is_ok = True
        for p in tmp:
            if m.replace('*', '') in p:
                is_ok = False
                break
        if is_ok:
            flag = True
            print(m)
    if flag:
        print()
        flag = False

    tmp = list(inrecs)
    tmp.sort()
    for p in tmp:
        if '.' in p:
            flag = True
            print(p)
    if flag:
        print()
        flag = False

    # if min_r > 0: 在函数里面处理比较好
    matchs = match_a_r_s(receivers)
    for m in matchs:
        is_ok = True
        for p in tmp:
            if m.replace('*', '') in p:
                is_ok = False
                break
        if is_ok:
            flag = True
            print(m)
    if flag:
        print()
        flag = False

    tmp = list(inservs)
    tmp.sort()
    for p in tmp:
        if '.' in p:
            flag = True
            print(p)
    if flag:
        print()
        flag = False

    matchs = match_a_r_s(services)
    for m in matchs:
        flag = True
        is_ok = True
        for p in tmp:
            if m.replace('*', '') in p:
                is_ok = False
                break
        if is_ok:
            print(m)
    if flag:
        print()
        flag = False

    print("AndroidManifest 统计:")
    print("PER MIN: %2d PER MAX: %2d" % (min_p, max_p))
    print("ACT MIN: %2d ACT MAX: %2d" % (min_a, max_a))
    print("REC MIN: %2d REC MAX: %2d" % (min_r, max_r))
    print("SER MIN: %2d SER MAX: %2d" % (min_s, max_s))

    if is_statistics:
        print("【TOTAL】", sum, '\n')
        print("【----- 清单统计 -----】")
        print("【Package】")
        for t in sorted(pkgd.items(), key=lambda d: d[1]):
            print(t)

        print("\n【Permissions】")
        for t in sorted(permd.items(), key=lambda d: d[1]):
            print(t)

        print("\n【Actions】")
        for t in sorted(actiond.items(), key=lambda d: d[1]):
            print(t)

        print("\n【Activities】")
        for t in sorted(activitiesd.items(), key=lambda d: d[1]):
            print(t)

        print("\n【Receivers】")
        for t in sorted(recd.items(), key=lambda d: d[1]):
            print(t)

        print("\n【Services】")
        for t in sorted(servd.items(), key=lambda d: d[1]):
            print(t)


def process_dex(data):
    global inSet

    try:
        dex = parsedex.DexFile(data)
    except Exception as e:
        print(e, "'s dex can not be parsed, please report to the author.")
        return

    tmpSet = set()
    for i in range(dex.string_ids.size):
        s = dex.string(i)
        tmpSet.add(s)

    if len(inSet) is 0:
        inSet = tmpSet
    else:
        inSet = inSet.intersection(tmpSet)


def in_dex(dir, arg_d):
    is_filter = False
    if arg_d == '1':
        is_filter = True
    rootdir = dir
    dex_name = "classes.dex"
    for parent, dirnames, filenames in os.walk(rootdir):
        for filename in filenames:
            # flag = 0
            filePath = os.path.join(parent, filename)
            process_apk(filePath, dex_name)

    apis = ""
    with open(os.path.join(sys.path[1], "cfg", 'api-versions.xml'), 'r', encoding='utf-8') as f:
        apis = f.read()

    strs = ""
    with open(os.path.join(sys.path[1], "cfg", 'strs.txt'), 'r', encoding='utf-8') as f:
        strs = f.read()

    apis = apis + strs

    inList = list(inSet)
    inList.sort()
    for s in inList:
        if isinstance(s, int) or isinstance(s, str):
            continue

        if len(s) < 4:
            continue

        s_decode = s.decode(errors='ignore')

        if is_filter and s_decode in apis:
            continue
        if is_filter and s_decode.startswith("L") and s_decode.endswith(";"):
            continue

        try:
            print('<!-- ', end='')
            print(s_decode, end=' ')
            print('-->', end='')
            print("", end='\n')
        except UnicodeEncodeError as e:
            print(e)
            continue


def in_file(rootdir):
    pass


def main(args):
    rootdir = args.dirName
    if not os.path.isdir(rootdir):
        print("Please give a correct directory.")
        return

    in_am(rootdir, args.s)

    if args.d:
        in_dex(rootdir, args.d)

    in_file(rootdir)


# APK必然存在共性
# APK
# - Manifest
# - Dex
#  - strings
#  - fields
#  - methods
#  - classes
#  - opcode series
# - Certificate
# - Resource
# - Assets
# File-Zip
# - 文件结构
# - 文件
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='inapk', description='Find out common feature from apks.')
    parser.add_argument('dirName')
    parser.add_argument('-s', action='store_true',
                        help='开启清单统计', required=False)
    #  amas/cfg/strs.txt 保存的没意义的字符串
    parser.add_argument(
        '-d', help='提取dex特征，0表示不过滤，1表示过滤，2过滤+模糊匹配，3过滤+统计', required=False)
    args = parser.parse_args()
    main(args)
