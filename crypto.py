import os
import struct
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)


def encrypt_session_key(public_key, session_key):
    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def decrypt_session_key(private_key, encrypted_session_key):
    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return session_key


def generate_aes_key():
    return AESGCM.generate_key(bit_length=256)


def aes_gcm_encrypt(session_key, plaintext: bytes):
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return nonce + ciphertext


def aes_gcm_decrypt(session_key, payload: bytes):
    aesgcm = AESGCM(session_key)

    nonce = payload[:12]
    ciphertext = payload[12:]

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext

def recv_exact(sock, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return b''
        buf.extend(chunk)
    return bytes(buf)


def send_framed(sock, data: bytes):
    sock.sendall(struct.pack('>I', len(data)) + data)


def recv_framed(sock):
    header = recv_exact(sock, 4)
    if not header:
        return None
    (length,) = struct.unpack('>I', header)
    data = recv_exact(sock, length)
    if not data and length != 0:
        return None
    return data
