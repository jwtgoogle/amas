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
import os
import os.path
import binascii

from axmlparser.axml import AXML


MAGIC_HEADERS = {b'504b0304': 'ZIP', b'7f454c46': 'ELF'}
AXML_MAGIC_HEADERS = [b'03000800', b'00000800']

is_first = True

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


def processZipFile(z):
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

    for name in z.namelist():
        try:
            data = z.read(name)
        except RuntimeError as err:
            print(name, err)
            continue

        magic_number = binascii.hexlify(data[:4])
        if name == "AndroidManifest.xml" and magic_number in AXML_MAGIC_HEADERS:
            a = AXML(data)

            p_set = set()
            pkg = a.getPackageName()
            p_set.add(pkg)
            if pkg not in pkgd.keys():
                pkgd[pkg] = 1
            else:
                pkgd[pkg] = pkgd[pkg] + 1

            a_set = set()
            for act in a.getActivities():
                a_set.add(act)
                if act in activitiesd.keys():
                    activitiesd[act] = activitiesd[act] + 1
                else:
                    activitiesd[act] = 1

                for word in act.split('.'):
                    a_set.add(word)
                    if word in activitiesd.keys():
                        activitiesd[word] = activitiesd[word] + 1
                    else:
                        activitiesd[act] = 1

            r_set = set()
            for r in a.getReceivers():
                r_set.add(r)
                if r not in recd.keys():
                    recd[r] = 1
                else:
                    recd[r] = recd[r] + 1

                for word in r.split('.'):
                    r_set.add(word)
                    if word not in recd.keys():
                        recd[word] = 1
                    else:
                        recd[word] = recd[word] + 1

            s_set = set()
            for r in a.getServices():
                s_set.add(r)
                for word in r.split('.'):
                    s_set.add(word)
                    if word not in servd.keys():
                        servd[word] = 1
                    else:
                        servd[word] = servd[word] + 1

            permissions = a.getPermissions()
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


def main(arg):
    if os.path.isdir(arg):
        rootdir = arg
        for parent, dirnames, filenames in os.walk(rootdir):
            for filename in filenames:
                filePath = os.path.join(parent, filename)
                # print(filePath)
                try:
                    with zipfile.ZipFile(filePath, 'r') as z:
                        processZipFile(z)
                except zipfile.BadZipFile as err:
                    print(filePath, err)

    print("Package")
    for t in sorted(pkgd.items(), key=lambda d: d[1]):
        print(t)
    if len(inpackage) == 1:
        print('''<stdmethod alias="A_FindNode" node_name="manifest" attr_name="package" attr_value="%s" clsid="{9C8E80D7-7D06-4bb5-9F3D-9533F97E3B67}"/>''' % inpackage.pop())

    print("\nPermissions :")
    for t in sorted(permd.items(), key=lambda d: d[1]):
        print(t)
    tmp = list(inperms)
    tmp.sort()
    for p in tmp:
        print('''<stdmethod alias="A_FindNode" node_name="uses-permission" attr_name="android:name" attr_value="%s" clsid="{9C8E80D7-7D06-4bb5-9F3D-9533F97E3B67}"/>''' % p)

    print("\nActions :")
    for t in sorted(actiond.items(), key=lambda d: d[1]):
        print(t)
    tmp = list(inacts)
    tmp.sort()
    for p in tmp:
        print('''<stdmethod alias="A_FindNode" node_name="action" attr_name="android:name" attr_value="%s" clsid="{9C8E80D7-7D06-4bb5-9F3D-9533F97E3B67}"/>''' % p)

    print("\nActivities :")
    for t in sorted(activitiesd.items(), key=lambda d: d[1]):
        print(t)
    tmp = list(inacivities)
    tmp.sort()
    for p in tmp:
        if '.' in p:
            print('''<stdmethod alias="A_FindNode" node_name="activity" attr_name="android:name" attr_value="%s" clsid="{9C8E80D7-7D06-4bb5-9F3D-9533F97E3B67}"/>''' % p)
    for p in tmp:
        if '.' not in p:
            print(p)

    print("\nReceivers :")
    for t in sorted(recd.items(), key=lambda d: d[1]):
        print(t)
    tmp = list(inrecs)
    tmp.sort()
    for p in tmp:
        if '.' in p:
            print('''<stdmethod alias="A_FindNode" node_name="receiver" attr_name="android:name" attr_value="%s" clsid="{9C8E80D7-7D06-4bb5-9F3D-9533F97E3B67}"/>''' % p)
    for p in tmp:
        if '.' not in p:
            print(p)

    print("\nServices :")
    for t in sorted(servd.items(), key=lambda d: d[1]):
        print(t)
    tmp = list(inservs)
    tmp.sort()
    for p in tmp:
        if '.' in p:
            print('''<stdmethod alias="A_FindNode" node_name="service" attr_name="android:name" attr_value="%s" clsid="{9C8E80D7-7D06-4bb5-9F3D-9533F97E3B67}"/>''' % p)
    for p in tmp:
        if '.' not in p:
            print(p)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog='axmlinfos', description='获取APK的整体信息，包含清单、文件。')
    parser.add_argument('dirName')
    args = parser.parse_args()
    main(args.dirName)
