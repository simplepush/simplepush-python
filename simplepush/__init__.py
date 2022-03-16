"""Library to interact with the Simplepush notification service."""
import base64
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import requests
import json
import asyncio
import time

DEFAULT_TIMEOUT = 5

SALT = '1789F0B8C4A051E5'

SIMPLEPUSH_URL = 'https://api.simplepush.io'


class BadRequest(Exception):
    """Raised when API thinks that title or message are too long."""
    pass


class UnknownError(Exception):
    """Raised for invalid responses."""
    pass

class FeedbackActionError(Exception):
    """Raised when feedback API is not reachable."""
    pass

class FeedbackActionTimeout(Exception):
    """Raised when a feedback action timed out."""
    pass


def send(key, message, title=None, event=None, actions=None, feedbackCallback=None, feedbackCallbackTimeout=60):
    """Send a plain-text message."""
    r = _send(key, message, title, event, actions)
    asyncio.run(handle_response(r, feedbackCallback, feedbackCallbackTimeout))


async def send_async(key, message, title=None, event=None, actions=None, feedbackCallback=None, feedbackCallbackTimeout=60):
    """Send a plain-text message."""
    r = _send(key, message, title, event, actions)
    await handle_response(r, feedbackCallback, feedbackCallbackTimeout)


def _send(key, message, title=None, event=None, actions=None):
    if not key or not message:
        raise ValueError("Key and message argument must be set")

    check_actions(actions)

    payload = generate_payload(key, title, message, event, actions, None, None)

    return requests.post(SIMPLEPUSH_URL + '/send', json=payload, timeout=DEFAULT_TIMEOUT)


def send_encrypted(key, password, salt, message, title=None, event=None, actions=None, feedbackCallback=None, feedbackCallbackTimeout=60):
    """Send an encrypted message."""
    r = _send_encrypted(key, password, salt, message, title, event, actions)
    asyncio.run(handle_response(r, feedbackCallback, feedbackCallbackTimeout))


async def send_encrypted_async(key, password, salt, message, title=None, event=None, actions=None, feedbackCallback=None, feedbackCallbackTimeout=60):
    """Send an encrypted message."""
    r = _send_encrypted(key, password, salt, message, title, event, actions)
    await handle_response(r, feedbackCallback, feedbackCallbackTimeout)


def _send_encrypted(key, password, salt, message, title=None, event=None, actions=None):
    if not key or not message or not password:
        raise ValueError("Key, message and password arguments must be set")

    check_actions(actions)

    payload = generate_payload(key, title, message, event, actions, password, salt)

    return requests.post(SIMPLEPUSH_URL + '/send', json=payload, timeout=DEFAULT_TIMEOUT)


async def handle_response(response, feedbackCallback, feedbackCallbackTimeout):
    """Raise error if message was not successfully sent."""
    if response.json()['status'] == 'BadRequest' and response.json()['message'] == 'Title or message too long':
        raise BadRequest

    if response.json()['status'] != 'OK':
        raise UnknownError

    if 'feedbackId' in response.json() and feedbackCallback is not None:
        feedbackId = response.json()['feedbackId']
        await query_feedback_endpoint(feedbackId, feedbackCallback, feedbackCallbackTimeout)

    response.raise_for_status()


def generate_payload(key, title, message, event=None, actions=None, password=None, salt=None):
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

    if actions:
        payload.update({'actions': actions})

    return payload


def generate_iv():
    """Generator for the initialization vector."""
    return os.urandom(algorithms.AES.block_size // 8)


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
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    data = padder.update(data.encode()) + padder.finalize()

    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), default_backend()).encryptor()
    return base64.urlsafe_b64encode(encryptor.update(data) + encryptor.finalize())


def check_actions(actions):
    """Raise error if actions can't be parsed"""
    if not isinstance(actions, list) and actions is not None:
        raise ValueError("Actions malformed")

    if isinstance(actions, list) and len(actions) > 0:
        if isinstance(actions[0], str):
            if not all(isinstance(el, str) for el in actions):
                raise ValueError("Feedback actions malformed")
        else:
            if not all('name' in el.keys() and 'url' in el.keys() for el in actions):
                raise ValueError("Get actions malformed")


async def query_feedback_endpoint(feedbackId, callback, timeout):
    stop = False
    n = 0
    start = time.time()

    while not stop:
        response = requests.get(SIMPLEPUSH_URL + '/1/feedback/' + feedbackId, timeout=DEFAULT_TIMEOUT)
        responseJson = response.json()
        if response.ok and responseJson['success']:
            if responseJson['action_selected']:
                stop = True

                callback(responseJson['action_selected'], responseJson['action_selected_at'], responseJson['action_delivered_at'], feedbackId)
            else:
                if timeout:
                    now = time.time()
                    if now > start + timeout:
                        stop = True
                        raise FeedbackActionTimeout("Feedback Action ID: " + feedbackId)

                if n < 60:
                    # In the first minute query every second
                    await asyncio.sleep(1)
                elif n < 260:
                    # In the ten minutes after the first minute query every 3 seconds
                    await asyncio.sleep(3)
                else:
                    # After 11 minutes query every five seconds
                    await asyncio.sleep(5)
        else:
            stop = True
            raise FeedbackActionError("Failed to reach feedback API.")
