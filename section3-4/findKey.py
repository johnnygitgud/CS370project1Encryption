#!/usr/bin/env python3
"""
findKey.py
Brute-force AES-128-CBC key (English word <16 chars padded with spaces) 
Plaintext file: 21 bytes ("This is a top secret.")
IV: 16 zero bytes
Target ciphertext (hex): 8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9
Reference: PyCryptodome CBC mode docs – https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html#cbc-mode
python3 -m pip install pycryptodome #use this command to install the necessary libraries.
"""

import sys
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


#Parameters
PLAINTEXT_FILE = 'plaintext3-4.txt' #File should be created before program is ran.
TARGET_HEX = '8d20e5056a8d24d0462ce74e4904c1b513e10d1df4a2ef2ad4540fae1ca0aaf9'
TARGET_BYTES = binascii.unhexlify(TARGET_HEX)
IV = b'\x00' * 16  # 16 zero bytes
BLOCK_SIZE = AES.block_size  # 16 bytes

#Encryption Function
def encrypt_aes128cbc(key16: bytes, data: bytes) -> bytes:
    cipher = AES.new(key16, AES.MODE_CBC, iv=IV)
    padded = pad(data, BLOCK_SIZE)
    ct = cipher.encrypt(padded)
    return ct

def main(wordlist_path: str):
    """
    Brute-force AES-128-CBC key using words from `wordlist_path`.

    Workflow:
    - Read plaintext from PLAINTEXT_FILE (must be exactly 21 bytes per assignment).
    - For each word in the wordlist:
        - encode to ASCII (skip words with non-ASCII chars)
        - skip words longer than 16 bytes
        - form 16-byte key by padding with space (0x20) on the right
        - encrypt plaintext with AES-128-CBC (IV = 16 zero bytes, PKCS#7 padding)
        - compare ciphertext to TARGET_BYTES; if equal, print result and exit
    """
    # Read plaintext (binary) and verify exact length required by the assignment.
    # Using a file ensures the bytes are exactly what the grader expects.
    with open(PLAINTEXT_FILE, 'rb') as f:
        plaintext = f.read()

    # Check for trailing newlines. Warn if length differs.
    if len(plaintext) != 21:
        print(f"Warning: plaintext length is {len(plaintext)} bytes (expected 21).")

    # Open the wordlist and iterate line-by-line so memory usage stays small.
    with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
        for lineno, line in enumerate(f, start=1):
            # Remove surrounding whitespace/newlines from the candidate word.
            word = line.strip()
            if not word:
                # skip empty lines
                continue

            # Convert to ASCII bytes. Non-ASCII words are skipped.
            try:
                wbytes = word.encode('ascii')
            except UnicodeEncodeError:
                # If a dictionary contains accented words, skip them.
                continue

            # Skip candidate words longer than 16 bytes; they cannot form AES-128 keys.
            if len(wbytes) > 16:
                continue

            # Form the 16-byte AES-128 key by right-padding with space (0x20).
            key16 = wbytes + b'\x20' * (16 - len(wbytes))

            # Encrypt the padded plaintext using AES-128-CBC with IV = all zeros.
            # The helper encrypt_aes128cbc handles PKCS#7 padding before encryption.
            ct = encrypt_aes128cbc(key16, plaintext)

            # If ciphertext matches the target bytes, the correct key is found.
            if ct == TARGET_BYTES:
                print(f"[Key] Word: '{word}' (line {lineno})")
                print("Key (hex):", binascii.hexlify(key16).decode())
                print("Ciphertext (hex):", binascii.hexlify(ct).decode())
                return 0

    # If loop completes without finding a match, report failure.
    print("No matching key found.")
    return 1


# system arguments makes sure to pass the filename that is used as argument to the word_listpath variable
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python3 findKey.py <words.txt>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
