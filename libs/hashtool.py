import hashlib
import io


def get_md5(filepath):
    md5 = hashlib.md5()
    f = io.FileIO(filepath, 'r')
    bytes = f.read(1024)
    while(bytes != b''):
        md5.update(bytes)
        bytes = f.read(1024)
    f.close()
    md = md5.hexdigest()

    return md


def get_sha256(filepath):
    sha1 = hashlib.sha256()
    block_size = 2*10

    with open(filepath, 'rb') as f:
        while True:
            data = f.read(block_size)
            if not data:
                break
            sha1.update(data)

    return sha1.hexdigest()
