import random
import string
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Password:
    def create(size:int = 20) -> str:
        letters = string.ascii_letters + string.digits
        result_str = [random.choice(letters) for i in range(size)]
        for _ in range(0, int(size / 3)):
            result_str[random.randint(0, size - 1)]= random.choice(string.punctuation)
            result_str[random.randint(0, size - 1)]= random.choice(string.punctuation)
        password =  ''.join(result_str)
        return password

    def encrypt(message, hash_256):
        iv = os.urandom(16)
        key = bytes.fromhex(hash_256)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        message = message.encode('utf-8')
        while len(message) % 16 > 0:
            message += b'\0'
        ct = encryptor.update(message) + encryptor.finalize()
        return iv.hex(), ct.hex()

    def decrypt(message, hash_256, iv):
        iv = bytes.fromhex(iv)
        key = bytes.fromhex(hash_256)
        ct = bytes.fromhex(message)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        message = decryptor.update(ct) + decryptor.finalize()
        while bytes(message[::-1][0]) == b'':
            message = message[:len(message) - 1]
        message = message.decode('utf-8')
        return message

if __name__ == '__main__':
    pwd = Password.create()
    print(pwd)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(''.encode())
    digest = digest.finalize().hex()
    iv, ct = Password.encrypt(pwd, digest)
    print(iv, ct)
    result = Password.decrypt(ct, digest, iv)
