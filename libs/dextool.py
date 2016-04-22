import zipfile
import os
import sys

from libs.enjarify import parsedex

def is_dex(filepath):
    DEX_MAGIC_HEADER = b'6465780a'
    try:
        with open(filepath, mode='rb') as f:
            data = f.read()

            import binascii
            magic_number = binascii.hexlify(data[:4])
            if magic_number == DEX_MAGIC_HEADER:
                return data
    except Exception as e:
        print(filepath, e)

    return None

def get_strings(filepath, is_filter=True):
    dex_datas = []
    if zipfile.is_zipfile(filepath):
        try:
            with zipfile.ZipFile(filepath, 'r') as z:
                for name in z.namelist():
                    if name.startswith('classes') and name.endswith('.dex'):
                        dex_datas.append(z.read(name))
        except Exception as e:
            print(filepath, e)
            return

    else:
        data = is_dex(filepath)
        if data:
            dex_datas.append(data)

    dex_files = []
    try:
        for dex_data in dex_datas:
            dex_files.append(parsedex.DexFile(dex_data))
    except Exception as e:
        print(filepath, e)
        return

    with open(os.path.join(sys.path[1], "cfg", 'strs.txt'), 'rb') as f:
        str_list = f.readlines()

    str_set = set(str_list)
    tmp_set = set()
    from time import clock
    for dex_file in dex_files:
        for i in range(dex_file.string_ids.size):
            s = dex_file.string(i)
            if is_filter and s + b'\r\n' in str_set:
                continue
            tmp_set.add(s)

    return tmp_set
