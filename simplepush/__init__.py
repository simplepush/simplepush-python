import base64
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import requests

SALT = "1789F0B8C4A051E5"

def send(key, title, message, event=None):
    if not key or not message:
        raise ValueError("Key and message argument must be set")

    payload = generate_payload(key, title, message, event, None, None)

    requests.post('https://api.simplepush.io/send', data = payload)

def send_encrypted(key, password, salt, title, message, event=None):
    if not key or not message or not password:
        raise ValueError("Key, message and password arguments must be set")

    payload = generate_payload(key, title, message, event, password, salt)

    requests.post('https://api.simplepush.io/send', data = payload)

def generate_payload(key, title, message, event=None, password=None, salt=None):
    payload = {"key" : key}

    if not password:
        payload.update({"msg" : message})

        if title:
            payload.update({"title" : title})

        if event:
            payload.update({"event" : event})
    else:
        encryption_key = generate_encryption_key(password, salt)
        iv = generate_iv()
        iv_hex = ""
        for c_idx in range(len(iv)):
            iv_hex += "{:02x}".format(ord(iv[c_idx:c_idx+1]))
        iv_hex = iv_hex.upper()

        payload.update({"encrypted" : "true", "iv" : iv_hex})

        if title:
            title = encrypt(encryption_key, iv, title)
            payload.update({"title" : title})

        if event:
            payload.update({"event" : event})

        message = encrypt(encryption_key, iv, message)
        payload.update({"msg" : message})

    return payload

def generate_iv():
    return os.urandom(algorithms.AES.block_size // 8)

def generate_encryption_key(password, salt=None):
    if salt:
        salted_password = password + salt
    else:
        # Compatibility for older versions
        salted_password = password + SALT
    hex_str = hashlib.sha1(salted_password.encode('utf-8')).hexdigest()[0:32]
    byte_str = bytearray.fromhex(hex_str)
    return bytes(byte_str)

def encrypt(encryption_key, iv, data):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    data = padder.update(data.encode()) + padder.finalize()

    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), default_backend()).encryptor()
    return base64.urlsafe_b64encode(encryptor.update(data) + encryptor.finalize())
