"""Library to interact with the Simplepush notification service."""
import base64
import hashlib

import requests
from Crypto import Random
from Crypto.Cipher import AES

DEFAULT_TIMEOUT = 5

SALT = '1789F0B8C4A051E5'

SIMPLEPUSH_URL = 'https://api.simplepush.io/send'


class BadRequest(Exception):
    """Raised when API thinks that title or message are too long."""
    pass


class UnknownError(Exception):
    """Raised for invalid responses."""
    pass


def send(key, title, message, event=None):
    """Send a plain-text message."""
    if not key or not message:
        raise ValueError("Key and message argument must be set")

    payload = generate_payload(key, title, message, event, None, None)

    r = requests.post(SIMPLEPUSH_URL, data=payload, timeout=DEFAULT_TIMEOUT)
    handle_response(r)


def send_encrypted(key, password, salt, title, message, event=None):
    """Send an encrypted message."""
    if not key or not message or not password:
        raise ValueError("Key, message and password arguments must be set")

    payload = generate_payload(key, title, message, event, password, salt)

    r = requests.post(SIMPLEPUSH_URL, data=payload, timeout=DEFAULT_TIMEOUT)
    handle_response(r)


def handle_response(response):
    """Raise error if message was not successfully sent."""
    if response.json()['status'] == 'BadRequest' and response.json()['message'] == 'Title or message too long':
        raise BadRequest

    if response.json()['status'] != 'OK':
        raise UnknownError

    response.raise_for_status()


def generate_payload(key, title, message, event=None, password=None, salt=None):
    """Generator for the payload."""
    payload = {'key': key}

    if not password:
        payload.update({'msg': message})

        if title:
            payload.update({'title': title})

        if event:
            payload.update({'event': event})
    else:
        encryption_key = generate_encryption_key(password, salt)
        iv = generate_iv()
        iv_hex = ""
        for c_idx in range(len(iv)):
            iv_hex += "{:02x}".format(ord(iv[c_idx:c_idx+1]))
        iv_hex = iv_hex.upper()

        payload.update({'encrypted': 'true', 'iv': iv_hex})

        if title:
            title = encrypt(encryption_key, iv, title)
            payload.update({'title': title})

        if event:
            payload.update({'event': event})

        message = encrypt(encryption_key, iv, message)
        payload.update({'msg': message})

    return payload


def generate_iv():
    """Generator for the initialization vector."""
    return Random.new().read(AES.block_size)


def generate_encryption_key(password, salt=None):
    """Create the encryption key."""
    if salt:
        salted_password = password + salt
    else:
        # Compatibility for older versions
        salted_password = password + SALT
    hex_str = hashlib.sha1(salted_password.encode('utf-8')).hexdigest()[0:32]
    byte_str = bytearray.fromhex(hex_str)
    return bytes(byte_str)


def encrypt(encryption_key, iv, data):
    """Encrypt the payload."""
    BS = 16
    pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

    data = pad(data)

    encrypted_data = AES.new(encryption_key, AES.MODE_CBC, IV=iv).encrypt(data)
    return base64.urlsafe_b64encode(encrypted_data)
