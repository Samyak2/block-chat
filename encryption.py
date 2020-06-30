import nacl.signing
import nacl.exceptions
import nacl.utils
import nacl.public

### Digital Signatures ###

def generate_signing_key() -> (nacl.signing.VerifyKey, nacl.signing.SigningKey):
    """Generate a new random signing key

    Returns:
    verify_key: key for verification, can be given out
    signing_key: secret signing key, do not give out
    """
    signing_key = nacl.signing.SigningKey.generate()

    verify_key = signing_key.verify_key

    return verify_key, signing_key

def encode_verify_key(verify_key: nacl.signing.VerifyKey) -> str:
    """Encodes given verify_key into a bytes object"""
    return verify_key.encode().hex()

def decode_verify_key(verify_key_hex: str) -> nacl.signing.VerifyKey:
    """Decodes given verify_key_hex into a verify_key"""
    return nacl.signing.VerifyKey(bytes.fromhex(verify_key_hex))

def sign_message(signing_key: nacl.signing.SigningKey, message):
    """Signs message using signing_key"""
    if isinstance(message, str):
        message = message.encode()
    signed = signing_key.sign(message)
    return signed.message, signed.signature

def verify_message(verify_key: nacl.signing.VerifyKey, message: bytes, signature: bytes):
    """Verifies that message has been signed by signature using the verify_key"""
    try:
        verify_key.verify(message, signature)
        return True
    except nacl.exceptions.BadSignatureError:
        return False

### END ###

### Public Key Encryption ###

def generate_keypair() -> (nacl.public.PublicKey, nacl.public.PrivateKey):
    """Generates a new random public-private key pair
    Returns:
    pk: public key
    sk: secret/private key
    """
    sk = nacl.public.PrivateKey.generate()
    pk = sk.public_key
    return pk, sk

def generate_box(one_sk: nacl.public.PrivateKey,
                 another_pk: nacl.public.PublicKey) -> nacl.public.Box:
    """Generates a secret box using one user's private key and another's public key"""
    return nacl.public.Box(one_sk, another_pk)

def encrypt_message(box: nacl.public.Box, message) -> bytes:
    """Encrypts message using box"""
    if isinstance(message, str):
        message = message.encode()
    return box.encrypt(message)

def decrypt_message(box: nacl.public.Box, encrypted: bytes) -> str:
    """Decryptes encrypted message using Box"""
    decrypted = box.decrypt(encrypted)
    return decrypted.decode('utf-8')

### END ###
