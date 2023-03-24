"""Library to interact with the Simplepush notification service."""
import base64
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import requests
import aiohttp
import asyncio
import time
from typing import Dict

DEFAULT_TIMEOUT = 5

SALT = '1789F0B8C4A051E5'

SIMPLEPUSH_URL = 'https://simplepu.sh'

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

class FeedbackUnavailable(Exception):
    """Raised when feedback doesn't exist."""
    pass


def send(key, message, title=None, password=None, salt=None, attachments = None, event=None, actions=None, feedback_callback=None, feedback_callback_timeout=60, ignore_connection_errors=True):
    """Send a plain-text message."""
    if not key or not message:
        raise ValueError("Key and message argument must be set")

    if password and not salt:
        raise ValueError("Salt is missing")

    if not password and salt:
        raise ValueError("Password is missing")

    _check_actions(actions)
    _check_attachments(attachments)

    payload, actions, actions_encrypted = _generate_payload(key, title, message, attachments, event, actions, password, salt)

    r = requests.post(SIMPLEPUSH_URL + '/send', json=payload, timeout=DEFAULT_TIMEOUT)
    _handle_response(r, actions, actions_encrypted, feedback_callback, feedback_callback_timeout, ignore_connection_errors)

async def async_send(key, message, title=None, password=None, salt=None, attachments=None, event=None, actions=None, feedback_callback=None, feedback_callback_timeout=60, ignore_connection_errors=True, aiohttp_session=None):
    """Send a plain-text message."""
    if not key or not message:
        raise ValueError("Key and message argument must be set")

    if password and not salt:
        raise ValueError("Salt is missing")

    if not password and salt:
        raise ValueError("Password is missing")

    _check_actions(actions)
    _check_attachments(attachments)

    payload, actions, actions_encrypted = _generate_payload(key, title, message, attachments, event, actions, password, salt)
    
    if aiohttp_session:
        async with aiohttp_session.post(SIMPLEPUSH_URL + '/send', json=payload) as resp:
            return await _async_handle_response(await resp.json(), actions, actions_encrypted, feedback_callback, feedback_callback_timeout,ignore_connection_errors, aiohttp_session)
    else:
        async with aiohttp.ClientSession(raise_for_status=True) as session:
            async with session.post(SIMPLEPUSH_URL + '/send', json=payload) as resp:
                return await _async_handle_response(await resp.json(), actions, actions_encrypted, feedback_callback, feedback_callback_timeout, ignore_connection_errors, session)

def _handle_response(response, actions, actions_encrypted, feedback_callback, feedback_callback_timeout, ignore_connection_errors):
    """Raise error if message was not successfully sent."""
    if response.json()['status'] == 'BadRequest' and response.json()['message'] == 'Title or message too long':
        raise BadRequest

    if response.json()['status'] != 'OK':
        raise UnknownError

    if 'feedbackId' in response.json() and feedback_callback is not None:
        feedback_id = response.json()['feedbackId']
        _query_feedback_endpoint(feedback_id, actions, actions_encrypted, feedback_callback, feedback_callback_timeout, ignore_connection_errors)

    response.raise_for_status()

async def _async_handle_response(json_response, actions, actions_encrypted, feedback_callback, feedback_callback_timeout, ignore_connection_errors, aiohttp_session):
    """Raise error if message was not successfully sent."""
    if json_response['status'] == 'BadRequest' and json_response['message'] == 'Title or message too long':
        raise BadRequest

    if json_response['status'] != 'OK':
        raise UnknownError

    if 'feedbackId' in json_response and feedback_callback is not None:
        feedback_id = json_response['feedbackId']
        await _async_query_feedback_endpoint(feedback_id, actions, actions_encrypted, feedback_callback, feedback_callback_timeout, ignore_connection_errors, aiohttp_session)

def _generate_payload(key, title, message, attachments=None, event=None, actions=None, password=None, salt=None):
    """Generator for the payload."""
    payload = {'key': key}
    actions_encrypted = None

    if not password:
        payload.update({'msg': message})

        if title:
            payload.update({'title': title})

        if event:
            payload.update({'event': event})

        if actions:
            payload.update({'actions': actions})

        if attachments:
            payload.update({'attachments': attachments})
    else:
        encryption_key = _generate_encryption_key(password, salt)
        iv = _generate_iv()
        iv_hex = ""
        for c_idx in range(len(iv)):
            iv_hex += "{:02x}".format(ord(iv[c_idx:c_idx+1]))
        iv_hex = iv_hex.upper()

        payload.update({'encrypted': 'true', 'iv': iv_hex})

        if title:
            title = _encrypt(encryption_key, iv, title)
            payload.update({'title': title})

        if event:
            payload.update({'event': event})

        message = _encrypt(encryption_key, iv, message)
        payload.update({'msg': message})

        if actions:
            actions_encrypted = []
            for action in actions:
                if isinstance(action, str):
                    # Feedback Action
                    actions_encrypted.append(_encrypt(encryption_key, iv, action))
                elif isinstance(action, Dict) and 'name' in action.keys() and 'url' in action.keys():
                    # GET Action
                    actions_encrypted.append({'name' : _encrypt(encryption_key, iv, action['name']), 'url' : _encrypt(encryption_key, iv, action['url'])})

            payload.update({'actions': actions_encrypted})

        if attachments:
            attachments_encrypted = []
            for attachment in attachments:
                if isinstance(attachment, Dict) and 'thumbnail' in attachment.keys() and 'video' in attachment.keys():
                    attachments_encrypted.append({'thumbnail' : _encrypt(encryption_key, iv, attachment['thumbnail']), 'video' : _encrypt(encryption_key, iv, attachment['video'])})
                elif isinstance(attachment, str):
                    attachments_encrypted.append(_encrypt(encryption_key, iv, attachment))

            payload.update({'attachments': attachments_encrypted})

    return payload, actions, actions_encrypted


def _generate_iv():
    """Generator for the initialization vector."""
    return os.urandom(algorithms.AES.block_size // 8)


def _generate_encryption_key(password, salt=None):
    """Create the encryption key."""
    if salt:
        salted_password = password + salt
    else:
        # Compatibility for older versions
        salted_password = password + SALT
    hex_str = hashlib.sha1(salted_password.encode('utf-8')).hexdigest()[0:32]
    byte_str = bytearray.fromhex(hex_str)
    return bytes(byte_str)


def _encrypt(encryption_key, iv, data):
    """Encrypt the payload."""
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    data = padder.update(data.encode()) + padder.finalize()

    encryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv), default_backend()).encryptor()
    return base64.urlsafe_b64encode(encryptor.update(data) + encryptor.finalize()).decode('ascii')


def _check_actions(actions):
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

def _check_attachments(attachments):
    if not isinstance(attachments, list) and attachments is not None:
        raise ValueError("Attachments malformed")

def _query_feedback_endpoint(feedback_id, actions, actions_encrypted, callback, timeout, ignore_connection_errors):
    stop = False
    n = 0
    start = time.time()

    while not stop:
        try:
            resp = requests.get(SIMPLEPUSH_URL + '/1/feedback/' + feedback_id)
            json = resp.json()
            if resp.ok and json['success']:
                if json['action_selected']:
                    stop = True

                    if actions_encrypted is None:
                        callback(json['action_selected'], json['action_selected_at'], json['action_delivered_at'], feedback_id)
                    else:
                        encrypted_action_selected = json['action_selected']
                        idx = actions_encrypted.index(encrypted_action_selected)
                        action_selected = actions[idx]
                        callback(action_selected, json['action_selected_at'], json['action_delivered_at'], feedback_id)
                else:
                    if timeout:
                        now = time.time()
                        if now > start + timeout:
                            stop = True
                            raise FeedbackActionTimeout("Feedback Action ID: " + feedback_id)

                    if n < 60:
                        # In the first minute query every second
                        time.sleep(1)
                    elif n < 260:
                        # In the ten minutes after the first minute query every two seconds
                        time.sleep(2)
                    else:
                        # After 11 minutes query every three seconds
                        time.sleep(3)
            else:
                if not ignore_connection_errors:
                    stop = True
                    raise FeedbackActionError("Failed to reach feedback API.")
                else:
                    time.sleep(5)
        except requests.exceptions.RequestException as e:
            if not ignore_connection_errors:
                stop = True
                raise FeedbackActionError("Failed to reach feedback API: " + str(e))
            else:
                time.sleep(5)

async def _async_query_feedback_endpoint(feedback_id, actions, actions_encrypted, callback, timeout, ignore_connection_errors, aiohttp_session):
    stop = False
    n = 0
    start = time.time()

    while not stop:
        try:
            async with aiohttp_session.get(SIMPLEPUSH_URL + '/1/feedback/' + feedback_id) as resp:
                json = await resp.json()
                if resp.ok and json['success']:
                    if json['action_selected']:
                        stop = True

                        if actions_encrypted is None:
                            callback(json['action_selected'], json['action_selected_at'], json['action_delivered_at'], feedback_id)
                        else:
                            encrypted_action_selected = json['action_selected']
                            idx = actions_encrypted.index(encrypted_action_selected)
                            action_selected = actions[idx]
                            callback(action_selected, json['action_selected_at'], json['action_delivered_at'], feedback_id)
                    else:
                        if timeout:
                            now = time.time()
                            if now > start + timeout:
                                stop = True
                                raise FeedbackActionTimeout("Feedback Action ID: " + feedback_id)

                        if n < 60:
                            # In the first minute query every second
                            await asyncio.sleep(1)
                        elif n < 260:
                            # In the ten minutes after the first minute query every two seconds
                            await asyncio.sleep(2)
                        else:
                            # After 11 minutes query every three seconds
                            await asyncio.sleep(3)
                else:
                    if not ignore_connection_errors:
                        stop = True
                        raise FeedbackActionError("Failed to reach feedback API.")
                    else:
                        time.sleep(5)
        except (aiohttp.ClientConnectionError, asyncio.TimeoutError) as e:
            if not ignore_connection_errors:
                stop = True
                raise FeedbackActionError("Failed to reach feedback API: " + str(e))
            else:
                await asyncio.sleep(5)
