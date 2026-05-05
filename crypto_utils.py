import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def derive_key(password: str):
    return hashlib.sha256(password.encode()).digest()

def encrypt_data(key, data):
    if isinstance(data, str):
        data = data.encode()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def decrypt_data(key, data):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv)) 
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()



def encrypt_file(key, data: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()


def decrypt_file(key, data: bytes):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()