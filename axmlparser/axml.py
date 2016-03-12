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
# limitations under the License.from xml.dom import minidom
from xml.sax.saxutils import escape
from struct import pack, unpack
from xml.dom import minidom

from .apk import AXMLParser
from .data import *


class AXML:

    def __init__(self, raw_buff):
        self.parser = AXMLParser(raw_buff)
        self.xmlns = False

        self.buff = ''
        self.content = {}
        self.permissions = set()

        self.activities = []
        self.mainActivity = None
        mainFlag = -2

        self.receivers = {}  # { rev : actions }
        self.services = {}  # { ser : actions }
        self.actions = set()
        action_list = []

        whichTag = -1
        tagName = ""
        ACT = 0
        REV = 1
        SER = 2

        tag = "notag"
        while True:
            _type = self.parser.next()

            if "</manifest>" in self.buff:
                break

            if _type == START_DOCUMENT:
                self.buff += '''<?xml version="1.0" encoding="utf-8"?>\n'''
            elif _type == START_TAG:
                prefix = self.getPrefix(
                    self.parser.getPrefix()) + self.parser.getName()

                if len(prefix) == 0:
                    tag = "notag"

                self.buff += '<' + prefix + '\n'
                self.buff += self.parser.getXMLNS()

                tag = prefix
                for i in range(0, int(self.parser.getAttributeCount())):
                    self.buff += "%s%s=\"%s\"\n" % (
                        self.getPrefix(self.parser.getAttributePrefix(i)),
                        self.parser.getAttributeName(i),
                        self._escape(self.getAttributeValue(i))
                    )

                self.buff += '>\n'

                if tag == "manifest" or tag == "uses-sdk":
                    for i in range(0, int(self.parser.getAttributeCount())):
                        name = self.parser.getAttributeName(i)
                        value = self._escape(self.getAttributeValue(i))
                        self.content[name] = value
                elif "permission" in tag:
                    for i in range(0, int(self.parser.getAttributeCount())):
                        name = self.parser.getAttributeName(i)
                        value = self._escape(self.getAttributeValue(i))
                        if name == "name":
                            self.permissions.add(value)
                            break
                elif tag == "application":
                    for i in range(0, int(self.parser.getAttributeCount())):
                        name = self.parser.getAttributeName(i)
                        value = self._escape(self.getAttributeValue(i))
                        if name == "name":
                            self.content["application"] = value
                            break
                elif tag == "activity":
                    whichTag = ACT
                    for i in range(0, int(self.parser.getAttributeCount())):
                        name = self.parser.getAttributeName(i)
                        value = self._escape(self.getAttributeValue(i))
                        # print(name)
                        if name == "name":
                            tagName = value
                            self.activities.append(value)
                elif tag == "receiver":
                    whichTag = REV
                    for i in range(0, int(self.parser.getAttributeCount())):
                        name = self.parser.getAttributeName(i)
                        value = self._escape(self.getAttributeValue(i))
                        if name == "name":
                            tagName = value
                            break
                elif tag == "service":
                    whichTag = SER
                    for i in range(0, int(self.parser.getAttributeCount())):
                        name = self.parser.getAttributeName(i)
                        value = self._escape(self.getAttributeValue(i))
                        if name == "name":
                            tagName = value
                            break
                elif tag == "action":
                    if whichTag == ACT:
                        for i in range(0, int(self.parser.getAttributeCount())):
                            name = self.parser.getAttributeName(i)
                            value = self._escape(self.getAttributeValue(i))
                            if name == "name":
                                self.actions.add(value)
                            if value == "android.intent.action.MAIN":
                                mainFlag += 1
                    elif whichTag == REV or whichTag == SER:
                        for i in range(0, int(self.parser.getAttributeCount())):
                            name = self.parser.getAttributeName(i)
                            value = self._escape(self.getAttributeValue(i))
                            if name == "name":
                                action_list.append(value)
                                self.actions.add(value)
                                break
                elif tag == 'category':
                    if whichTag == ACT:
                        for i in range(0, int(self.parser.getAttributeCount())):
                            value = self._escape(self.getAttributeValue(i))
                            if value == "android.intent.category.LAUNCHER":
                                mainFlag += 1
                else:
                    for i in range(0, int(self.parser.getAttributeCount())):
                        name = self.parser.getAttributeName(i)
                        value = self._escape(self.getAttributeValue(i))
                        if "permission" in value:
                            self.permissions.add(value)
                        else:
                            self.content[name] = value
                        # print("other >>>> ", key, name, value)

            elif _type == END_TAG:
                prefix = self.getPrefix(
                    self.parser.getPrefix()) + self.parser.getName()
                if len(prefix) == 0:
                    prefix = "notag"
                self.buff += "</%s>\n" % (prefix)

                if prefix == "activity":
                    if mainFlag == 0:
                        self.mainActivity = tagName
                    mainFlag = -2
                    whichTag = -1
                elif prefix == "receiver":
                    whichTag = -1
                    self.receivers[tagName] = action_list
                    action_list = []
                elif prefix == "service":
                    whichTag = -1
                    self.services[tagName] = action_list
                    action_list = []

            elif _type == TEXT:
                self.buff += "%s\n" % self.parser.getText()

            elif _type == END_DOCUMENT:
                break

    # pleed patch
    def _escape(self, s):
        s = s.replace("&", "&amp;")
        s = s.replace('"', "&quot;")
        s = s.replace("'", "&apos;")
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
        return escape(s)

    def get_buff(self):
        return self.buff

    def get_xml(self):
        return minidom.parseString(self.get_buff()).toprettyxml()

    def get_xml_obj(self):
        return minidom.parseString(self.get_buff())

    def getPrefix(self, prefix):
        if prefix is None or len(prefix) == 0:
            return ''

        return prefix + ':'

    def getAttributeValue(self, index):
        # print('getAttributeValue : ', index)
        _type = self.parser.getAttributeValueType(index)
        _data = self.parser.getAttributeValueData(index)

        if _type == TYPE_STRING:
            return self.parser.getAttributeValue(index)

        elif _type == TYPE_ATTRIBUTE:
            return "?%s%08X" % (self.getPackage(_data), _data)

        elif _type == TYPE_REFERENCE:
            return "@%s%08X" % (self.getPackage(_data), _data)

        elif _type == TYPE_FLOAT:
            return "%f" % unpack("=f", pack("=L", _data))[0]

        elif _type == TYPE_INT_HEX:
            return "0x%08X" % _data

        elif _type == TYPE_INT_BOOLEAN:
            if _data == 0:
                return "false"
            return "true"

        elif _type == TYPE_DIMENSION:
            return "%f%s" % (self.complexToFloat(_data), DIMENSION_UNITS[_data & COMPLEX_UNIT_MASK])

        elif _type == TYPE_FRACTION:
            return "%f%s" % (self.complexToFloat(_data), FRACTION_UNITS[_data & COMPLEX_UNIT_MASK])

        elif _type >= TYPE_FIRST_COLOR_INT and _type <= TYPE_LAST_COLOR_INT:
            return "#%08X" % _data

        elif _type >= TYPE_FIRST_INT and _type <= TYPE_LAST_INT:
            return "%d" % int(_data)

        return "<0x%X, type 0x%02X>" % (_data, _type)

    def complexToFloat(self, xcomplex):
        return (float)(xcomplex & 0xFFFFFF00) * RADIX_MULTS[(xcomplex >> 4) & 3]

    def getPackage(self, id):
        if id >> 24 == 1:
            return "android:"
        return ""

    def getPackageName(self):
        return self.content['package']

    def getVersionCode(self):
        return self.content['versionCode']

    def getVersionName(self):
        return self.content['versionName']

    def getMinSdkVersion(self):
        if 'minSdkVersion' in self.content.keys():
            return self.content['minSdkVersion']
        else:
            return 3

    def getTargetSdkVersion(self):
        if 'targetSdkVersion' in self.content.keys():
            return self.content['targetSdkVersion']
        else:
            return self.getMinSdkVersion()

    def getPermissions(self):
        return self.permissions

    def getActions(self):
        return self.actions

    def getApplicationName(self):
        if 'application' in self.content:
            return self.content['application']

    def getActivities(self):
        return self.activities

    def getMainActivity(self):
        return self.mainActivity

    def getReceivers(self):
        return self.receivers

    def getServices(self):
        return self.services

    def printAll(self):
        print("package : ", self.getPackageName())
        print("application : ", self.getApplicationName())

        print("main activity : ", self.getMainActivity())
        print("Activities : ")
        for act in sorted(self.activities):
            print(" ", act)

        print("Receivers : ", )
        for key in sorted(self.receivers.keys()):
            print(" ", key, self.receivers[key])

        print("Services : ")
        for key in sorted(self.services.keys()):
            print(" ", key, self.services[key])

        print("permissions : ")
        for perm in sorted(self.permissions):
            print(" ", perm)

    def printXML(self):
        print(self.get_xml())

if __name__ == '__main__':
    # TODO 如何修改为测试模式
    axml = AXML(open("axml/test/AndroidManifest.xml", "rb").read())
    axml.printAll()
