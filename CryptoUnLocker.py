#!/usr/bin/env python3

import struct
import os
import argparse
import shutil
import sys
import csv
import re
from collections import namedtuple
from datetime import datetime

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1
from Crypto.Util.number import bytes_to_long


PUBLICKEYSTRUC = namedtuple('PUBLICKEYSTRUC', 'bType bVersion reserved aiKeyAlg')
RSAPUBKEY = namedtuple('RSAPUBKEY', 'magic bitlen pubexp')
PRIVATEKEYBLOB = namedtuple('PRIVATEKEYBLOB', 'modulus prime1 prime2 exponent1 exponent2 coefficient privateExponent')

PUBLICKEYSTRUC_s = struct.Struct('<bbHI')
RSAPUBKEY_s = struct.Struct('<4sII')

key_re = re.compile(r'-----BEGIN.*KEY-----\n(.*)\n-----END.*KEY-----', re.DOTALL)


class OutputLevel:
    VerboseLevel, InfoLevel, WarnLevel, ErrorLevel = range(4)


class CryptoUnLocker:
    def __init__(self):
        self.keys = []

    def load_key_from_paste(self):
        print("Please paste your RSA private key below, including the -----BEGIN RSA PRIVATE KEY----- and -----END RSA PRIVATE KEY----- lines:")
        key_paste = ""
        while True:
            try:
                line = input()
                if not line:
                    break
                key_paste += line + "\n"
            except EOFError:
                break
        
        # Try importing the key directly
        self.load_key_from_string(key_paste)

    def load_key_from_string(self, s):
        try:
            r = RSA.import_key(s)
            self.keys.append(r)
            print("Key successfully imported")
        except ValueError as e:
            print(f"Error importing key: {e}")

    def crypt_import_key(self, d):
        publickeystruc = PUBLICKEYSTRUC._make(PUBLICKEYSTRUC_s.unpack_from(d))
        if publickeystruc.bType == 7 and publickeystruc.bVersion == 2 and publickeystruc.aiKeyAlg == 41984:
            rsapubkey = RSAPUBKEY._make(RSAPUBKEY_s.unpack_from(d[8:]))
            if rsapubkey.magic == b'RSA2':
                bitlen8 = rsapubkey.bitlen // 8
                bitlen16 = rsapubkey.bitlen // 16
                private_key_blob_s = struct.Struct(f'{bitlen8}s{bitlen16}s{bitlen16}s{bitlen16}s{bitlen16}s{bitlen16}s{bitlen8}s')
                privatekey = PRIVATEKEYBLOB._make(map(bytes_to_long, private_key_blob_s.unpack_from(d[20:])))
                
                r = RSA.construct((privatekey.modulus, rsapubkey.pubexp, privatekey.privateExponent,
                                   privatekey.prime1, privatekey.prime2))
                self.keys.append(r)
                return True
        return False

    def is_cryptolocker(self, fn):
        with open(fn, 'rb') as f:
            file_header = f.read(0x114)
        if len(file_header) != 0x114:
            return False
        return SHA1.new(b'\x00' * 4 + file_header[0x14:0x114]).digest() == file_header[:0x14]

    def decrypt_file(self, fn):
        with open(fn, 'rb') as fp:
            file_header = fp.read(0x114)
            if len(file_header) != 0x114:
                raise Exception("Not a CryptoLocker file")

            aes_key = next((self.retrieve_aes_key(r, file_header) for r in self.keys if self.retrieve_aes_key(r, file_header)), None)
            if not aes_key:
                raise Exception("Could not find the private key for this CryptoLocker file")

            cipher = AES.new(aes_key, AES.MODE_CBC, b'\x00' * 16)
            decrypted_data = cipher.decrypt(fp.read())
            return decrypted_data.rstrip(decrypted_data[-1:])

    def retrieve_aes_key(self, r, file_header):
        file_header = file_header[0x14:0x114][::-1]
        cipher = PKCS1_v1_5.new(r)
        blob = cipher.decrypt(file_header, None)
        if blob and len(blob) >= 0x2c and blob[:4] == b'\x08\x02\x00\x00':
            return blob[0x0c:0x0c+32]
        return None


class CryptoUnLockerProcess:
    def __init__(self, args, unlocker):
        self.args = args
        self.unlocker = unlocker
        self.csvfp = open(args.csvfile, 'w', newline='') if args.csvfile else None
        self.csv = csv.writer(self.csvfp) if self.csvfp else None
        if self.csv:
            self.csv.writerow(['Timestamp', 'Filename', 'Message'])

    def doit(self):
        # Prompt user to paste RSA private key
        self.unlocker.load_key_from_paste()

        if not self.unlocker.keys and not self.args.detect:
            self.output(OutputLevel.ErrorLevel, '', 'No keys were successfully loaded. Exiting.')
            return 1

        for root, _, files in os.walk(self.args.encrypted_filenames[0]) if self.args.recursive else [(None, None, self.args.encrypted_filenames)]:
            for fn in files:
                self.process_file(root or '', fn)
        return 0

    def process_file(self, pathname, fn):
        fullpath = os.path.join(pathname, fn)
        try:
            if not self.unlocker.is_cryptolocker(fullpath):
                self.output(OutputLevel.VerboseLevel, fullpath, "Not a CryptoLocker file")
                return
            
            decrypted_file = self.unlocker.decrypt_file(fullpath)
            self.output(OutputLevel.InfoLevel, fullpath, "Successfully decrypted file")
            
            if not self.args.dry_run:
                # Ensure destination directory exists only if 'destdir' is provided
                if self.args.destdir:
                    dest_path = os.path.join(self.args.destdir, pathname)  # Full destination path
                    os.makedirs(dest_path, exist_ok=True)  # Create the directory if it doesn't exist
                else:
                    dest_path = pathname  # Use the current path if 'destdir' is not provided

                # Add '.decrypted' to the filename
                decrypted_filename = f"{os.path.splitext(fn)[0]}.decrypted{os.path.splitext(fn)[1]}"
                
                # Write decrypted file to destination with '.decrypted' suffix
                with open(os.path.join(dest_path, decrypted_filename), 'wb') as f:
                    f.write(decrypted_file)
        except Exception as e:
            self.output(OutputLevel.ErrorLevel, fullpath, f"Unsuccessful decrypting file: {str(e)}")


    def output(self, level, fn, msg):
        if level == OutputLevel.VerboseLevel and not self.args.verbose:
            return
        if self.csv:
            self.csv.writerow([datetime.now(), fn, msg])
        print(f"{'[+] ' if level == OutputLevel.InfoLevel else '[-] '}{msg}: {fn}")


def main():
    parser = argparse.ArgumentParser(description='Decrypt CryptoLocker encrypted files.')
    parser.add_argument('--detect', action='store_true', help='Detect CryptoLocker files without decrypting')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursive search')  # Add this line
    parser.add_argument('-v', action='store_true', help='Verbose output')
    parser.add_argument('--dry-run', action='store_true', help='Dry run mode')
    parser.add_argument('-o', dest='destdir', help='Output directory')
    parser.add_argument('--csv', dest='csvfile', help='CSV output file')
    parser.add_argument('encrypted_filenames', nargs='+')
    return CryptoUnLockerProcess(parser.parse_args(), CryptoUnLocker()).doit()


if __name__ == '__main__':
    sys.exit(main())
