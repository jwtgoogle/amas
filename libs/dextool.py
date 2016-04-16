import zipfile
import os
import sys

from libs.enjarify import parsedex

def is_dex(filepath):
    # MAGIC_HEADERS = {b'504b0304': 'ZIP', b'7f454c46': 'ELF'}
    # AXML_MAGIC_HEADERS = [b'03000800', b'00000800']
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

def get_strings(filepath):
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

    strs = ""
    with open(os.path.join(sys.path[1], "cfg", 'strs.txt'), 'r', encoding='utf-8') as f:
        strs = f.read()

    tmp_set = set()
    for dex_file in dex_files:
        for i in range(dex_file.string_ids.size):
            s = dex_file.string(i)
            if s.decode(errors='ignore') in strs:
                continue
            tmp_set.add(s)

    return tmp_set
