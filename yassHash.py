#!/usr/bin/python3

import sys
import hashlib

def hash(nomeFile, hash):
    try:
        fO = open(nomeFile + '-' + hash, 'w')
        with open(nomeFile) as f:
            for l in f:
                l = l.rstrip()
                if str(hash).upper() == 'MD5':
                    result = hashlib.md5(str(l).encode())
                elif str(hash).upper() == 'SHA1':
                    result = hashlib.sha1(str(l).encode())
                elif str(hash).upper() == 'SHA256':
                    result = hashlib.sha256(str(l).encode())
                elif str(hash).upper() == 'SHA384':
                    result = hashlib.sha384(str(l).encode())
                elif str(hash).upper() == 'SHA512':
                    result = hashlib.sha512(str(l).encode())
                fO.write(l + ':' + result.hexdigest() + '\n')
        fO.close()
    except:
        print('\nERRORE: impossibile aprire il file ' + sys.argv[2])

if __name__ == '__main__':
    if (len(sys.argv) < 3) or (len(sys.argv) > 3):
        print('\nUSO: hashFile md5|sha1|sha256|sha384|sha512 nomefile.txt')
        print('ESEMPIO: hashFile md5 mysecretpass.txt')
    else:
        if (str(sys.argv[1]).upper() != 'MD5') and (str(sys.argv[1]).upper() != 'SHA1') and (str(sys.argv[1]).upper() != 'SHA256') and (str(sys.argv[1]).upper() != 'SHA384') and (str(sys.argv[1]).upper() != 'SHA512'):
            print('\nERRORE. Hashing supportati: MD5, SHA1, SHA256, SHA384, SHA512')
        else:
            print('\nHash scelto\t : ' + str(sys.argv[1]).upper())
            print('Nome file input\t : ' + sys.argv[2])
            print('Nome file output : ' + sys.argv[2] + '-' + sys.argv[1] + '.txt\n')

            hash(sys.argv[2], sys.argv[1])
