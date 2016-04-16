import difflib
from difflib import SequenceMatcher


def get_wildcards(str1, str2, min_length=0):
    '''
        获取2个字符串的通配符字符串,
        length，2个*之间的字符串的最小长度，默认为0。
        如果小于这个长度，那么会变成*；如果min_length=1，*a* -> *
    '''
    diff = difflib.Differ().compare(str1, str2)
    wildcards = ''
    for item in list(diff):
        if '-' in item or '+' in item:
            if not wildcards.endswith('*'):
                wildcards = wildcards + '*'
        else:
            wildcards = wildcards + item.strip()

    if not wildcards:
        return wildcards

    result = ''
    if min_length > 0:
        if wildcards[0] == '*':
            result = '*'
        is_first = True
        for item in wildcards.split('*'):
            if is_first:
                is_first = False
                if len(item) < min_length and not result.endswith('*'):
                    result = result + '*'
            elif not result.endswith('*'):
                result = result + '*'
            if len(item) > min_length:
                result = result + item
    else:
        result = wildcards

    return result

def get_wildcards_in_list(str_list, min_length=0):
    '''
        获取一个通配字符串，可以通配符该列表里面所有的字符串。
    '''
    wildcards = str_list[0]
    str_list.remove(wildcards)
    for item in str_list:
        wildcards = get_wildcards(wildcards, item, min_length)

    return wildcards


def get_best_wildcard_from_list(str1, str_list, min_length=0):
    '''
        从列表str_list中，找出一个与str最相似的通配字符串。
    '''
    best_radio = 0
    best_str = ''
    for sss in str_list:
        radio = get_radio(str1, sss)
        if best_radio < radio:
            best_radio = radio
            best_str = sss

    return get_wildcards(str1, best_str, min_length)


def get_radio(str1, str2):
    return SequenceMatcher(None, str1, str2).ratio()


if __name__ == '__main__':
    # axbc%efg#dbddd
    # azbc$efg@oodbbcs
    #
    print(get_wildcards('aaaxbc@efg#dbddd', 'aaaixzbc$efg@oodbbcs'))
    print(get_wildcards('aaaxbc@efg#dbddd', 'aaaixzbc$efg@oodbbcs', 1))
    print(get_wildcards('aaaxbc@efg#dbddd', 'aaaixzbc$efg@oodbbcs', 2))
