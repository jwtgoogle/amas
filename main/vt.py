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

import argparse
import os.path
import urllib.request
import urllib.parse
import hashlib
import simplejson

from libs import hashtool


# Sending and scanning files, file size limit is 32MB.
url_scan = "https://www.virustotal.com/vtapi/v2/file/scan"
# Rescanning already submitted files
url_rescan = "https://www.virustotal.com/vtapi/v2/file/rescan"
# Retrieving file scan reports
url_report = 'https://www.virustotal.com/vtapi/v2/file/report'



def get_vt_result(resource):
    print("HASH :", resource)
    params = urllib.parse.urlencode(
        {"resource": resource, "apikey": "8aa8e064de88be3f9ebff2ad406ff141f53b853331927daf3ccac114e8f8d0db"})
    f = urllib.request.urlopen(url_rescan, params.encode('utf-8'))
    json = simplejson.loads(f.read())
    response_code = json.get("response_code")

    if response_code == 0:
        print("Need to upload file ...[TODO]")
        # TODO if not found , upload file
        return

    f = urllib.request.urlopen(url_report, params.encode('utf-8'))
    json = f.read()
    response_dict = simplejson.loads(json)
    print('Detection ratio:', str(response_dict.get("positives", 0)) +
          '/' + str(response_dict.get("total", 0)))
    scans_result = response_dict.get("scans", {})
    antivirus = sorted(list(scans_result.keys()), key=str.lower)
    for key in antivirus:
        result = scans_result.get(key, {}).get("result")
        if result:
            print(key, ' ' * (20 - len(key)), result, ' ' *
                  (40 - len(result)), scans_result.get(key, {}).get("update"))


def main(resource):
    if os.path.isfile(resource):
        resource = hashtool.get_sha256(resource)
    elif os.path.isdir(resource):
        for parent, dirnames, filenames in os.walk(resource):
            for filename in filenames:
                filepath = os.path.join(parent, filename)
                resource = hashtool.get_sha256(filepath)
                get_vt_result(resource)
    elif len(resource) not in [32, 40, 64] or not resource.isalnum():
        print(resource, "is NOT a md5/sha1/sha256 hash! Please try again.")

    get_vt_result(resource)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='vt', description='get vt result')
    parser.add_argument(
        'resource', help='a md5/sha1/sha256 hash, or file/dir path')

    main(parser.parse_args().resource)
