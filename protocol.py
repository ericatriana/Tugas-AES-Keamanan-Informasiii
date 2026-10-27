"""JSON-line TCP transport, AES-CBC + encrypt-then-MAC with HMAC-SHA256."""
import json
import hmac
import hashlib
import socket
import secrets
from aes import cbc_encrypt, cbc_decrypt

LIMIT = 65536

def send(sock, obj):
    data = json.dumps(obj, separators=(',',':'), ensure_ascii=True).encode('ascii') + b'\n'
    if len(data) > LIMIT:
        raise ValueError('Message too large')
    sock.sendall(data)

def receive(sock):
    parts = bytearray()
    while True:
        c = sock.recv(1)
        if not c:
            raise ConnectionError('Connection closed')
        if c == b'\n':
            break
        parts += c
        if len(parts) > LIMIT:
            raise ValueError('Message too large')
    return json.loads(parts.decode('ascii'))

def ascii_bytes(value):
    return value.encode('ascii')

def seal(obj, key):
    raw = json.dumps(obj, separators=(',',':'), sort_keys=True,ensure_ascii=True).encode('ascii')
    cipher = cbc_encrypt(raw, key)
    # Domain separation: MAC key derivation is pedagogical; use a standard KDF in production.
    mac_key = hashlib.sha256(b'ki-demo-mac-v1'+key).digest()
    tag = hmac.new(mac_key, cipher, hashlib.sha256).hexdigest().upper()
    return {'ciphertext':cipher.hex().upper(),'tag':tag}

def open_seal(packet, key):
    ciphertext = bytes.fromhex(packet['ciphertext'])
    tag = bytes.fromhex(packet['tag'])
    mac_key = hashlib.sha256(b'ki-demo-mac-v1'+key).digest()
    expected = hmac.new(mac_key, ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(expected,tag):
        raise ValueError('Authentication failed (wrong key or modified packet)')
    return json.loads(cbc_decrypt(ciphertext,key).decode('ascii'))

def read_key(name):
    import getpass
    while True:
        value = getpass.getpass(f'{name} (16 karakter ASCII): ')
        try:
            b = ascii_bytes(value)
        except UnicodeEncodeError:
            print('Wajib ASCII.');continue
        if len(b)==16:
            return b
        print('Harus tepat 16 byte.')

def connect(host, port):
    return socket.create_connection((host, port),timeout=15)
