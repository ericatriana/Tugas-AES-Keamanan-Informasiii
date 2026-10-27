"""AES-128 from scratch (educational). No cryptography dependency."""
import secrets


def gf_mul(a, b):
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        a = ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xff
        b >>= 1
    return out


def rotl(b, n):
    return ((b << n) | (b >> (8-n))) & 255


def inverse(b):
    if b == 0:
        return 0
    p, n = b, 254
    out = 1
    while n:
        if n & 1:
            out = gf_mul(out, p)
        p = gf_mul(p, p)
        n >>= 1
    return out


def sbox_value(b):
    v = inverse(b)
    return (v ^ rotl(v, 1) ^ rotl(v, 2) ^ rotl(v, 3) ^ rotl(v, 4) ^ 0x63) & 255

SBOX = [sbox_value(i) for i in range(256)]
INV_SBOX = [0]*256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i


def expand(key):
    if len(key) != 16:
        raise ValueError('AES-128 requires 16-byte key')
    words = [list(key[i:i+4]) for i in range(0, 16, 4)]
    rcon = 1
    while len(words) < 44:
        tmp = words[-1][:]
        if len(words) % 4 == 0:
            tmp = tmp[1:] + tmp[:1]
            tmp = [SBOX[x] for x in tmp]
            tmp[0] ^= rcon
            rcon = gf_mul(rcon, 2)
        words.append([a ^ b for a, b in zip(words[-4], tmp)])
    return [sum(words[4*i:4*i+4], []) for i in range(11)]


def add_key(s, k):
    return [a ^ b for a, b in zip(s, k)]


def shift_rows(s, inverse=False):
    o = s[:]
    for row in range(4):
        for col in range(4):
            o[4*col+row] = s[4*((col+(-row if inverse else row))%4)+row]
    return o


def mix_columns(s, inv=False):
    mat = ((14,11,13,9),(9,14,11,13),(13,9,14,11),(11,13,9,14)) if inv else ((2,3,1,1),(1,2,3,1),(1,1,2,3),(3,1,1,2))
    out = s[:]
    for c in range(4):
        v = s[c*4:c*4+4]
        for r in range(4):
            out[c*4+r] = gf_mul(mat[r][0],v[0]) ^ gf_mul(mat[r][1],v[1]) ^ gf_mul(mat[r][2],v[2]) ^ gf_mul(mat[r][3],v[3])
    return out


def encrypt_block(block, key):
    if len(block) != 16:
        raise ValueError('AES block must be 16 bytes')
    keys = expand(key)
    s = add_key(list(block), keys[0])
    for i in range(1, 10):
        s = add_key(mix_columns(shift_rows([SBOX[x] for x in s])), keys[i])
    return bytes(add_key(shift_rows([SBOX[x] for x in s]), keys[10]))


def decrypt_block(block, key):
    if len(block) != 16:
        raise ValueError('AES block must be 16 bytes')
    keys = expand(key)
    s = add_key(list(block), keys[10])
    for i in range(9, 0, -1):
        s = [INV_SBOX[x] for x in shift_rows(s, True)]
        s = mix_columns(add_key(s, keys[i]), True)
    return bytes(add_key([INV_SBOX[x] for x in shift_rows(s, True)], keys[0]))


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def cbc_encrypt(data, key):
    """Return iv||ciphertext. For integrity, use EtM HMAC in protocol.py."""
    iv = secrets.token_bytes(16)
    pad = 16 - len(data) % 16
    data += bytes([pad])*pad
    previous = iv
    output = bytearray(iv)
    for i in range(0, len(data), 16):
        previous = encrypt_block(xor(data[i:i+16], previous), key)
        output.extend(previous)
    return bytes(output)


def cbc_decrypt(data, key):
    if len(data) < 32 or len(data) % 16:
        raise ValueError('Bad ciphertext size')
    previous = data[:16]
    output = bytearray()
    for i in range(16, len(data), 16):
        block = data[i:i+16]
        output.extend(xor(decrypt_block(block,key), previous))
        previous = block
    pad = output[-1]
    if not 1 <= pad <= 16 or output[-pad:] != bytes([pad])*pad:
        raise ValueError('Bad padding')
    return bytes(output[:-pad])
