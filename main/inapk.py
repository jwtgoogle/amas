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
from difflib import SequenceMatcher

from libs.enjarify import parsedex
from libs.axmlparser.axml import AXML
from libs import strtool
from libs import dextool

MAGIC_HEADERS = {b'504b0304': 'ZIP', b'7f454c46': 'ELF'}
AXML_MAGIC_HEADERS = [b'03000800', b'00000800']
DEX_MAGIC_HEADERS = [b'6465780a']

is_first_axml = True

pkgd = {}
inpackage = set()
permd = {}
inperms = set()
actiond = {}
inacts = set()

activitiesd = {} # activity:count
inacivities = set()
recd = {} # receiver : count
inrecs = set()
servd = {} #  # service:count
inservs = set()

# dex_strings_dict = {}
strs_list = []
dex_strings_inset = {}

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


# FIXME 这里最好是单纯的返回，解析后的axml数据，数据处理也许应该放在外面
def process_axml(data):
    global is_first_axml

    # 存放的是清单的绝对公共特征
    global inpackage
    global inperms
    global inacts
    global inacivities
    global inrecs
    global inservs

    # 字典存放着各个节点的数量
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

    axml = AXML(data)

    pkg_tmp_set = set()
    pkg = axml.getPackageName()
    pkg_tmp_set.add(pkg)
    if pkg not in pkgd.keys():
        pkgd[pkg] = 1
    else:
        pkgd[pkg] = pkgd[pkg] + 1

    a_set = set()
    tmp = axml.getActivities()

    if len(tmp) < min_a:
        min_a = len(tmp)
    if len(tmp) > max_a:
        max_a = len(tmp)

    tmp_list = []
    for activity in axml.getActivities():
        activity = activity.replace(pkg, '')
        a_set.add(activity)
        tmp_list.append(activity)
        if activity in activitiesd.keys():
            activitiesd[activity] = activitiesd[activity] + 1
        else:
            activitiesd[activity] = 1

    activities.append(tmp_list)

    r_set = set()
    tmp = axml.getReceivers()
    if len(tmp) < min_r:
        min_r = len(tmp)
    if len(tmp) > max_r:
        max_r = len(tmp)

    tmp_list = []
    for r in axml.getReceivers():
        r = r.replace(pkg, '')
        r_set.add(r)
        tmp_list.append(r)
        if r not in recd.keys():
            recd[r] = 1
        else:
            recd[r] = recd[r] + 1

    receivers.append(tmp_list)

    s_set = set()
    tmp = axml.getServices()
    if len(tmp) < min_s:
        min_s = len(tmp)
    if len(tmp) > max_s:
        max_s = len(tmp)

    tmp_list = []
    for s in axml.getServices():
        s = s.replace(pkg, '')
        s_set.add(s)
        tmp_list.append(s)
        if s not in servd.keys():
            servd[s] = 1
        else:
            servd[s] = servd[s] + 1

    services.append(tmp_list)

    permissions = axml.getUsesPermissions()
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
    if int(axml.getMinSdkVersion()) <= 3 and int(axml.getTargetSdkVersion()) <= 3:
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

    actions = axml.getActions()
    for key in actions:
        if key not in actiond.keys():
            actiond[key] = 1
        else:
            actiond[key] = actiond[key] + 1

    if is_first_axml:
        is_first_axml = False
        inpackage = pkg_tmp_set
        inperms = axml.getUsesPermissions()
        inacts = axml.getActions()
        inacivities = a_set
        inrecs = r_set
        inservs = s_set
    else:
        inpackage = inpackage & pkg_tmp_set
        inperms = inperms & axml.getUsesPermissions()
        inacts = inacts & axml.getActions()
        inacivities = inacivities & a_set
        inrecs = inrecs & r_set
        inservs = inservs & s_set


def get_dex_datas(file_path):
    dex_datas = []
    if zipfile.is_zipfile(file_path):
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                for name in z.namelist():
                    if name.startswith('classes') and name.endswith('.dex'):
                        dex_datas.append(z.read(name))
        except zipfile.BadZipfile as e:
            print(file_path, e)
    return dex_datas


def get_manifest_wildcards(lists, inset):
    list0 = lists[0]
    lists.remove(list0)
    patterns = set()
    for item0 in list0:
        pattern = item0
        for sub_list in lists:
            pattern = strtool.get_best_wildcard_from_list(pattern, sub_list, 2)
        if pattern and pattern != '*':
            patterns.add(pattern)

    return patterns


def in_manifest(rootdir, is_statistics, is_fuzzy=False):
    sum = 0
    am_name = "AndroidManifest.xml"

    result_dict = dict()
    for parent, dirnames, filenames in os.walk(rootdir):
        for filename in filenames:
            filepath = os.path.join(parent, filename)
            if zipfile.is_zipfile(filepath):
                try:
                    with zipfile.ZipFile(filepath, 'r') as z:
                        z.testzip()
                        if "AndroidManifest.xml" not in z.namelist():
                            continue
                        try:
                            data = z.read("AndroidManifest.xml")
                        except RuntimeError as err:
                            print(filepath, err)
                            continue

                        process_axml(data)
                except zipfile.BadZipFile as err:
                    print(filepath, err)
                    continue
                sum = sum + 1

    if len(inperms) > 0:
        tmp = list(inperms)
        tmp.sort()
        result_dict['Permissions'] = tmp

    if len(inacts) > 0:
        tmp = list(inacts)
        tmp.sort()
        result_dict["Actions"] = tmp

    if is_fuzzy:
        pkgs = []
        for item in pkgd.items():
            pkgs.append(item[0])
        tmp_pkg = []
        wildcards = strtool.get_wildcards_in_list(pkgs, 1)
        if len(wildcards) > 1:
            tmp_pkg.append(wildcards)
            result_dict['Package'] = tmp_pkg

        wildcards = get_manifest_wildcards(activities, inacivities)
        if wildcards:
            result_dict["Fuzzy_Activities"] = wildcards

        wildcards = get_manifest_wildcards(receivers, inrecs)
        if wildcards:
            result_dict["Fuzzy_Receivers"] = wildcards

        wildcards = get_manifest_wildcards(services, inservs)
        if len(wildcards) > 0:
            result_dict["Fuzzy_Services"] = wildcards
    else:
        if len(inacivities) > 0:
            result_dict["Activities"] = inacivities
        if len(inrecs) > 0:
            result_dict["Receivers"] = inrecs
        if len(inservs) > 0:
            result_dict["Services"] = inservs

    count_list = [min_p, max_p, min_a, max_a, min_r, max_r, min_s, max_s]
    result_dict["Manifest_Count"] = count_list

    if not is_statistics:
        return result_dict

    print('\n')
    print('-'*20, 'Statistics', '-'*20)

    print("\nPackage:", sum)
    max_len = 0
    for item in pkgd.items():
        if max_len < len(item[0]):
            max_len = len(item[0])
    for t in sorted(pkgd.items(), key=lambda d: d[1]):
        print(t[0], ' ' * (max_len - len(t[0])), format(t[1], '2.0f'), format(t[1]/sum, '0.2f'))

    print("\nPermissions:", sum)
    max_len = 0
    for item in permd.items():
        if max_len < len(item[0]):
            max_len = len(item[0])
    for t in sorted(permd.items(), key=lambda d: d[1]):
        print(t[0], ' ' * (max_len - len(t[0])), format(t[1], '2.0f'), format(t[1]/sum, '0.2f'))

    print("\nActions:", sum)
    max_len = 0
    for item in actiond.items():
        if max_len < len(item[0]):
            max_len = len(item[0])
    for t in sorted(actiond.items(), key=lambda d: d[1]):
        print(t[0], ' ' * (max_len - len(t[0])), format(t[1], '2.0f'), format(t[1]/sum, '0.2f'))

    print("\nActivities:", sum)
    max_len = 0
    for item in activitiesd.items():
        if max_len < len(item[0]):
            max_len = len(item[0])
    for t in sorted(activitiesd.items(), key=lambda d: d[1]):
        print(t[0], ' ' * (max_len - len(t[0])), format(t[1], '2.0f'), format(t[1]/sum, '0.2f'))

    print("\nReceivers:", sum)
    max_len = 0
    for item in recd.items():
        if max_len < len(item[0]):
            max_len = len(item[0])
    for t in sorted(recd.items(), key=lambda d: d[1]):
        print(t[0], ' ' * (max_len - len(t[0])), format(t[1], '2.0f'), format(t[1]/sum, '0.2f'))

    print("\nServices:", sum)
    for t in sorted(servd.items(), key=lambda d: d[1]):
        print(t[0], ' ' * (max_len - len(t[0])), format(t[1], '2.0f'), format(t[1]/sum, '0.2f'))


    return result_dict

def process_dex(data):
    global dex_strings_inset
    global dex_strings_dict

    try:
        dex = parsedex.DexFile(data)
    except Exception as e:
        print(e, "'s dex can not be parsed, please report to the author.")
        return

    tmpSet = set()
    tmp_list = []
    for i in range(dex.string_ids.size):
        s = dex.string(i)
        if s in dex_strings_dict.keys():
            dex_strings_dict[s] = dex_strings_dict[s] + 1
        else:
            dex_strings_dict[s] = 1

        if len(s) > 5:
            tmpSet.add(s)

    strs_list.append(tmpSet)

    if len(dex_strings_inset) is 0:
        dex_strings_inset = tmpSet
    else:
        dex_strings_inset = dex_strings_inset & tmpSet


def get_dex_strings(dex_datas):
    global dex_strings_inset

    dex_files = []
    try:
        for dex_data in dex_datas:
            dex_files.append(parsedex.DexFile(dex_data))
    except Exception as e:
        print(e, "'s dex can not be parsed, please report to the author.")
        return

    strs = ""
    with open(os.path.join(sys.path[1], "cfg", 'strs.txt'), 'r', encoding='utf-8') as f:
        strs = f.read()

    tmp_set = set()
    tmp_list = []
    for dex_file in dex_files:
        for i in range(dex_file.string_ids.size):
            s = dex_file.string(i)
            if s.decode(errors='ignore') in strs:
                continue
            tmp_set.add(s)

    strs_list.append(tmp_set)

    if len(dex_strings_inset) is 0:
        dex_strings_inset = tmp_set
    else:
        dex_strings_inset = dex_strings_inset & tmp_set


def save_cache(strs, filename):
    path = os.path.join(sys.path[1], 'cache', filename)
    with open(path, 'w', encoding='utf-8') as f:
        for s in strs:
            f.write(s.decode(encoding='utf-8', errors='ignore') + '\n')


def is_cache(filename):
    path = os.path.join(sys.path[1], 'cache', filename)
    return os.path.exists(path)


def read_cache(filename):
    path = os.path.join(sys.path[1], 'cache', filename)
    with open(path, 'r', encoding='utf-8') as f:
        strs = set()
        lines = f.readlines()
        for line in lines:
            strs.add(line[:-1].encode(errors='ignore'))

        return strs


def in_dex_strings(dir, hex_flag, is_fuzzy=False):
    rootdir = dir
    dexs_strings_list = [] # 将每一个APK的字符串集合，当作一个元素，存放在这个列表里面
    dexs_common_strings = set()
    is_first = True
    for parent, dirnames, filenames in os.walk(rootdir):
        for filename in filenames:
            filepath = os.path.join(parent, filename)

            if is_cache(filename):
                strset = read_cache(filename)
            else:
                strset = dextool.get_strings(filepath)
                save_cache(strset, filename)

            dexs_strings_list.append(strset)
            # print(len(strset), 'ok')

            if is_first and strset:
                dexs_common_strings = strset
                is_first = False
            elif strset:
                dexs_common_strings = dexs_common_strings & strset

    if not is_fuzzy:
        return (dexs_common_strings, None)

    str_list = []
    dexs_strings_list_0 = dexs_strings_list[0]
    for item in dexs_strings_list_0 - dexs_common_strings:
        str_list.append(item.decode(errors='ignore'))
    dexs_strings_list.remove(dexs_strings_list_0)

    wildcards_set = set(str_list)
    for ss2 in dexs_strings_list:
        tmp_sss = []
        for item in ss2 - dexs_common_strings:
            tmp_sss.append(item.decode(errors='ignore'))

        tmp = set()
        for s1 in wildcards_set:
            wildcards = strtool.get_best_wildcard_from_list(s1, tmp_sss, 1)
            if len(wildcards.replace('*', '')) > 3:
                tmp.add(wildcards)
        wildcards_set.clear()
        wildcards_set = tmp

    return (dexs_common_strings, wildcards_set)


def in_resources(rootdir, is_all):
    name_set = set()
    crc_set = set()
    is_first = True
    for parent, dirnames, filenames in os.walk(rootdir):
        for filename in filenames:
            filePath = os.path.join(parent, filename)

            if not zipfile.is_zipfile(filePath):
                continue

            result = get_file_set(filePath, is_all)
            if not result:
                continue

            if is_first:
                name_set = result[0]
                crc_set = result[1]
                is_first = False
            else:
                name_set = name_set & result[0]
                crc_set = crc_set & result[1]

    tmp = set()
    for item in name_set:
        if item.startswith('META-INF/') or item in ['AndroidManifest.xml', 'resources.arsc']:
            tmp.add(item)
        elif item.startswith('classes') and item.endswith('.dex'):
            tmp.add(item)

    for item in tmp:
        name_set.remove(item)

    return (name_set, crc_set)


def get_file_set(file_path, is_all):
    HEADERS = { b'03000800':'AXML', b'89504e47':'PNG', }
    crc_set = set()
    nameset = set()
    try:
        with zipfile.ZipFile(file_path, 'r') as z:
            z.testzip()
            for info in z.infolist():
                if not is_all:
                    data = z.read(info.filename)
                    magic_number = binascii.hexlify(data[:4])
                    if magic_number in HEADERS.keys():
                        continue

                crc = str(hex(info.CRC)).upper()[2:]
                crc = '0'*(8-len(crc)) + crc
                crc_set.add(info.filename + "_" + crc)
                nameset.add(info.filename)

            return (nameset, crc_set)

    except zipfile.BadZipFile as err:
        print(file_path, err)
        return False


def in_dex_opcodes(rootdir, is_fuzzy, is_object):
    '''
        rootdir  目录
        is_fuzzy 是否模糊匹配
        is_object 是否匹配父类为Object的类
    '''
    ops_set = set()
    fuzzy_ops_set = set()
    method_dict = dict()
    is_first = True
    for parent, dirnames, filenames in os.walk(rootdir):
        for filename in filenames:
            filepath = os.path.join(parent, filename)
            dexs = get_dex_datas(filepath)

            if len(dexs) == 0:
                continue

            ops_set2 = set()
            tmp_set = set()
            if is_first:
                print(filename)
                for data in dexs:
                    result = get_opcodes(data)
                    ops_set2 = ops_set2 | result
                ops_set = ops_set2
                is_first = False
            else:
                for data in dexs:
                    result = get_opcodes(data)
                    ops_set2 = ops_set2 | get_opcodes(data)

                for ops1, proto1, sup1, mtd1 in ops_set:
                    if not is_object and sup1 == 'Ljava/lang/Object;':
                        continue

                    for ops2, proto2, sup2, mtd2 in ops_set2:
                        # proto一样，父类一样，opcode一样
                        if proto1 == proto2 and sup1 == sup2 and ops1 == ops2:
                            tmp_set.add((ops1, proto1, sup1, mtd1))
                            break
                        elif proto1 == proto2 and ops1 == ops2:
                            tmp_set.add((ops1, proto1, sup1, mtd1))
                            break
                        elif proto1 == proto2 and ops1 in ops2 or ops2 in ops1:
                            tmp_set.add((ops1, proto1, sup1, mtd1))
                            break

                        if is_fuzzy:
                            if proto1 == proto2:
                                ratio = SequenceMatcher(None, ops1, ops2).ratio()
                                if ratio > 0.4:
                                    from libs import strtool
                                    pattern = strtool.get_wildcards(ops1, ops2)
                                    arr = pattern.split("*")
                                    max_len = 0
                                    for item in arr:
                                        if max_len < len(item):
                                            max_len = len(item)
                                    if max_len < 10:
                                        continue
                                    tmp_set.add((pattern, proto1, sup1, mtd1))
                                    break
                ops_set.clear()
                ops_set = tmp_set

    for ops1, proto1, sup1, mtd1 in ops_set:
        print(ops1, proto1, sup1, mtd1)


def get_opcodes(data):
    '''
        不解析Android API相关的类
        不解析父类为自定义类的类
    '''
    with open(os.path.join(sys.path[1], "cfg", 'classes.txt'), \
            'r', encoding='utf-8') as f:
        apis = f.read()

    dexFile = parsedex.DexFile(data)
    opcode_set = set()
    for dexClass in dexFile.classes:
        if dexClass.name.decode() in apis:
            continue

        if dexClass.super.decode() not in apis:
            continue

        dexClass.parseData()
        for method in dexClass.data.methods:
            id =  method.id
            opcodes = ''
            if method.code is None:
                continue

            for bc in method.code.bytecode:
                opcode = str(hex(bc.opcode)).upper()[2:]
                if len(opcode) == 2:
                    opcodes = opcodes + opcode
                else:
                    opcodes = opcodes + "0" + opcode

            if len(opcodes) < 20:
                continue

            method_sign = "L" + id.cname.decode() + ";->" \
                         + id.name.decode() + id.desc.decode()
            proto = get_proto_string(id.return_type, id.param_types)
            super_class = 'L' + dexClass.super.decode() + ';'
            opcode_set.add((opcodes, proto, super_class, method_sign))

    return opcode_set


def get_proto_string(return_type, param_types):
    r = return_type.decode()
    if len(r) > 1:
        r = 'L'

    ps = ''
    for pt in param_types:
        p = pt.decode()
        if len(p) > 1:
            ps = ps + 'L'
        else:
            ps = ps + p

    return r + ps


def main(args):
    rootdir = args.dir
    if not os.path.isdir(rootdir):
        print("Please give a correct directory.")
        return

    if args.m and args.M:
        print('Only use one of m and M!')
        return

    if args.r and args.R:
        print('Only use one of r and R!')
        return

    if args.o and args.O:
        print('Only use one of o and O!')
        return

    if args.m:
        result = in_manifest(rootdir, False, args.f)
        keys = list(result.keys())
        keys.sort()
        for key in keys:
            print(key)
            if key == 'Manifest_Count':
                count_list = result[key]
                print("PER MIN: %2d PER MAX: %2d" % (count_list[0], count_list[1]))
                print("ACT MIN: %2d ACT MAX: %2d" % (count_list[2], count_list[3]))
                print("REC MIN: %2d REC MAX: %2d" % (count_list[4], count_list[5]))
                print("SER MIN: %2d SER MAX: %2d" % (count_list[6], count_list[7]))
                print()
                continue
            for value in result[key]:
                print(value)
            print('')

    elif args.M:
        result = in_manifest(rootdir, True, args.f)

    if args.s:
        # TODO 如果APK没有classes.dex，或者解析出错，打印出来
        result = in_dex_strings(rootdir, False, args.f)
        print("Dex Strings:")
        strs = list(result[0])
        strs.sort()
        for s in strs:
            print(s)

        if result[1]:
            print("\nDex Fuzzy Strings:")
            strs = list(result[1])
            strs.sort()
            for s in strs:
                print(s)

    if args.r:
        name_set, crc_set = in_resources(rootdir, False)
    elif args.R:
        name_set, crc_set = in_resources(rootdir, False)


    if args.r or args.R:
        print('\nFiles:')
        for name in sorted(list(name_set)):
            if not name.endswith("/"):
                print(name)

        if len(crc_set) > 0:
            print("\nFiles CRC:")
            for name in sorted(list(crc_set)):
                print(name)


    if args.o:
        in_dex_opcodes(rootdir, args.f, False) # 精准，排除Object
    elif args.O:
        in_dex_opcodes(rootdir, args.f, True) # 精准，包含Object


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='inapk', description='Find out common feature from apks.')
    parser.add_argument('dir')
    parser.add_argument('-m', action='store_true', help='manifest', required=False)
    parser.add_argument('-M', action='store_true', help='manifest, with statistics', required=False)
    parser.add_argument('-r', action='store_true', help='resources, exclude AXML, PNG', required=False)
    parser.add_argument('-R', action='store_true', help='All resources', required=False)
    parser.add_argument('-s', action='store_true', help='dex strings.', required=False)
    # parser.add_argument('-S', action='store_true', help='dex strings with hex.', required=False)
    parser.add_argument('-o', action='store_true', help='dex opcodes, precise matching and not suport java/lang/Object.', required=False)
    parser.add_argument('-O', action='store_true', help='dex opcodes, precise matching all classes.', required=False)
    parser.add_argument('-f', action='store_true', help='open fuzzing', required=False)

    args = parser.parse_args()
    main(args)
