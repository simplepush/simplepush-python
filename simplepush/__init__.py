import base64
from Crypto import Random
from Crypto.Cipher import AES
import hashlib
import requests

SALT = "1789F0B8C4A051E5"

def send(key, title, message, event=None):
    if not key or not message:
        raise ValueError("Key and message argument must be set")

    payload = generate_payload(key, title, message, event, None)

    requests.post('https://api.simplepush.io/send', data = payload)

def send_encrypted(key, password, title, message, event=None):
    if not key or not message or not password:
        raise ValueError("Key, message and password arguments must be set")

    payload = generate_payload(key, title, message, event, password)

    requests.post('https://api.simplepush.io/send', data = payload)

def generate_payload(key, title, message, event=None, password=None):
    payload = {"key" : key}

    if not password:
        payload.update({"msg" : message})

        if title:
            payload.update({"title" : title})

        if event:
            payload.update({"event" : event})
    else:
        encryption_key = generate_encryption_key(password)
        iv = generate_iv()
        iv_hex = "".join("{:02x}".format(ord(c)) for c in iv).upper()

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
    return Random.new().read(AES.block_size)

def generate_encryption_key(password):
    hex_str = hashlib.sha1(password + SALT).hexdigest()[0:32]
    byte_str = str(bytearray.fromhex(hex_str))
    return byte_str

def encrypt(encryption_key, iv, data):
    BS = 16
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 

    data = pad(data)

    encrypted_data = AES.new(encryption_key, AES.MODE_CBC, IV=iv).encrypt(data)
    return base64.urlsafe_b64encode(encrypted_data)
