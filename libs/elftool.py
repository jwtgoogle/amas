from libs.pyelftools.elf.elffile import ELFFile
from libs.pyelftools.common.exceptions import ELFError
from libs.pyelftools.common.py3compat import (ifilter, byte2int, bytes2str, itervalues, str2bytes)


def get_strings(filepath):
    pass


def get_text_strings(filepath):
    pass


def get_rodata_strings(filepath):
    with open(filepath, 'rb') as file:
        try:
            elffile = ELFFile(file)
            display_string_dump(elffile, '.rodata')
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
        return

    print("\nString dump of section '%s':" % section.name)

    found = False
    data = section.data()
    dataptr = 0

    while dataptr < len(data):
        while ( dataptr < len(data) and
                not (32 <= byte2int(data[dataptr]) <= 127)):
            dataptr += 1

        if dataptr >= len(data):
            break

        endptr = dataptr
        while endptr < len(data) and byte2int(data[endptr]) != 0:
            endptr += 1

        found = True
        try:
            print(bytes2str(data[dataptr:endptr]))
        except UnicodeEncodeError as e:
            print(data[dataptr:endptr])

        dataptr = endptr

    if not found:
        print('  No strings found in this section.')


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
