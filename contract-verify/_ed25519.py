"""
Minimal, dependency-free Ed25519 (RFC 8032).

This is the public-domain reference construction, using Python's built-in
pow() for modular exponentiation so it is fast enough for a demo while staying
pure stdlib. It exists so the example runs anywhere with plain `python3`, no
pip install required.

Public API:
    keypair(seed: bytes = None) -> (private_key: bytes, public_key: bytes)
    sign(message: bytes, private_key: bytes, public_key: bytes) -> bytes
    verify(signature: bytes, message: bytes, public_key: bytes) -> bool
"""

import hashlib
import os

b = 256
q = 2 ** 255 - 19
ell = 2 ** 252 + 27742317777372353535851937790883648493


def _H(m):
    return hashlib.sha512(m).digest()


def _inv(x):
    return pow(x, q - 2, q)


_d = (-121665 * _inv(121666)) % q
_I = pow(2, (q - 1) // 4, q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (q + 3) // 8, q)
    if (x * x - xx) % q != 0:
        x = (x * _I) % q
    if x % 2 != 0:
        x = q - x
    return x


_By = (4 * _inv(5)) % q
_Bx = _xrecover(_By)
_B = [_Bx % q, _By % q]


def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    denom_x = _inv(1 + _d * x1 * x2 * y1 * y2)
    denom_y = _inv(1 - _d * x1 * x2 * y1 * y2)
    x3 = (x1 * y2 + x2 * y1) * denom_x
    y3 = (y1 * y2 + x1 * x2) * denom_y
    return [x3 % q, y3 % q]


def _scalarmult(P, e):
    result = [0, 1]
    base = P
    while e > 0:
        if e & 1:
            result = _edwards(result, base)
        base = _edwards(base, base)
        e >>= 1
    return result


def _encodeint(y):
    return bytes([(y >> (8 * i)) & 0xFF for i in range(b // 8)])


def _encodepoint(P):
    x, y = P
    val = y | ((x & 1) << (b - 1))
    return bytes([(val >> (8 * i)) & 0xFF for i in range(b // 8)])


def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1


def _decodeint(s):
    return sum(2 ** i * _bit(s, i) for i in range(0, b))


def _Hint(m):
    h = _H(m)
    return sum(2 ** i * _bit(h, i) for i in range(2 * b))


def _isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % q == 0


def _decodepoint(s):
    y = sum(2 ** i * _bit(s, i) for i in range(0, b - 1))
    x = _xrecover(y)
    if x & 1 != _bit(s, b - 1):
        x = q - x
    P = [x, y]
    if not _isoncurve(P):
        raise ValueError("decoding point that is not on curve")
    return P


def _secret_scalar(h):
    a = 2 ** (b - 2)
    for i in range(3, b - 2):
        a += 2 ** i * _bit(h, i)
    return a


def keypair(seed=None):
    if seed is None:
        seed = os.urandom(32)
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _H(seed)
    a = _secret_scalar(h)
    A = _scalarmult(_B, a)
    return seed, _encodepoint(A)


def sign(message, private_key, public_key):
    h = _H(private_key)
    a = _secret_scalar(h)
    r = _Hint(h[b // 8:b // 4] + message)
    R = _scalarmult(_B, r)
    S = (r + _Hint(_encodepoint(R) + public_key + message) * a) % ell
    return _encodepoint(R) + _encodeint(S)


def verify(signature, message, public_key):
    try:
        if len(signature) != b // 4 or len(public_key) != b // 8:
            return False
        R = _decodepoint(signature[0:b // 8])
        A = _decodepoint(public_key)
        S = _decodeint(signature[b // 8:b // 4])
        h = _Hint(_encodepoint(R) + public_key + message)
        return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))
    except (ValueError, IndexError):
        return False
