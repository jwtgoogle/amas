import sys
import binascii
from libs import dextool
from libs import elftool

if __name__ == '__main__':
    if len(sys.argv) == 2:
        if elftool.is_elf(sys.argv[1]):
            for h in elftool.get_rodata_strings(sys.argv[1]):
                try:
                    print(binascii.a2b_hex(h).decode(errors='ignore'))
                except:
                    print(binascii.a2b_hex(h))
    else:
        print(
'''get rodata strings
Usage:
    grod so_path
        ''')
