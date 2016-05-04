import sys
from libs import dextool
from libs import elftool

if __name__ == '__main__':
    if len(sys.argv) == 2:
        elftool.get_rodata_strings(sys.argv[1])
    else:
        print(
'''get rodata strings
Usage:
    grod so_path
        ''')
