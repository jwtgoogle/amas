import binascii
from libs.pyelftools.elf.elffile import ELFFile
from libs.pyelftools.common.exceptions import ELFError
from libs.pyelftools.common.py3compat import (ifilter, byte2int, bytes2str, itervalues, str2bytes)


def is_elf(filepath):
    ELF_MAGIC_HEADER = b'7f454c46'
    try:
        with open(filepath, mode='rb') as f:
            data = f.read()

            magic_number = binascii.hexlify(data[:4])
            if magic_number == ELF_MAGIC_HEADER:
                return data
    except Exception as e:
        print(filepath, e)

    return None


def get_strings(filepath):
    pass


def get_text_strings(filepath):
    pass


def get_rodata_strings(filepath):
    with open(filepath, 'rb') as file:
        try:
            elffile = ELFFile(file)
            return display_string_dump(elffile, '.rodata')
        except ELFError as ex:
            sys.stderr.write('ELF error: %s\n' % ex)
            sys.exit(1)


def display_string_dump(elffile, section_spec):
    """ Display a strings dump of a section. section_spec is either a
        section number or a name.
    """
    section = _section_from_spec(elffile, section_spec)
    if section is None:
        print("Section '%s' does not exist in the file!" % (
            section_spec))
        return None

    data = section.data()
    dataptr = 0

    strs = []
    while dataptr < len(data):
        while ( dataptr < len(data) and
                not (32 <= byte2int(data[dataptr]) <= 127)):
            dataptr += 1

        if dataptr >= len(data):
            break

        endptr = dataptr
        while endptr < len(data) and byte2int(data[endptr]) != 0:
            endptr += 1

        strs.append(binascii.b2a_hex(data[dataptr:endptr]).decode().upper())
        dataptr = endptr

    return strs

def _section_from_spec(elffile, spec):
    """ Retrieve a section given a "spec" (either number or name).
        Return None if no such section exists in the file.
    """
    try:
        num = int(spec)
        if num < elffile.num_sections():
            return elffile.get_section(num)
        else:
            return None
    except ValueError:
        # Not a number. Must be a name then
        return elffile.get_section_by_name(spec)
