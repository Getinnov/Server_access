from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import hashes

encode = 'utf-8'

class Ed25519:
    def create(seed: str = None) -> bytes:
        """
        generate ED25519 from seed if provided else random
        warning: using a seed is not secure !
        """
        private_key = Ed25519PrivateKey.generate()
        if seed is not None:
            digest = hashes.Hash(hashes.SHA256())
            digest.update(seed.encode(encode))
            private_key = Ed25519PrivateKey.from_private_bytes(
                digest.finalize()
            )
        return private_key

    def private_key_enc(private_key: Ed25519PrivateKey , password: str = None) -> str:
        """
        return private bytes PEM formated for any ed25519 private key object
        """
        encr_algo = serialization.NoEncryption()
        if password is not None:
            encr_algo = serialization.BestAvailableEncryption(
                password.encode(encode)
            )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encr_algo
        ).decode(encode)
        return private_pem

    def private_key_dec(private_key: str, password: str = None) -> Ed25519PrivateKey:
        """
        return private key object from PEM a formated key
        """
        if password is not None:
            password = password.encode(encode)
        private = serialization.load_pem_private_key(
            private_key.encode(encode),
            password=password,
            backend=default_backend()
        )
        return private

    def get_public(private_key: Ed25519PrivateKey) -> Ed25519PublicKey:
        """
        return public key object from private key object
        """
        return private_key.public_key()

    def public_key_enc(public_key: Ed25519PublicKey) -> str:
        """
        return public bytes PEM formated for any ed25519 public key object
        """
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(encode)
        return public_pem

    def public_key_dec(public_key: str) -> Ed25519PublicKey:
        """
        return public key object from PEM formated ed25519 public key
        """
        public = serialization.load_pem_public_key(
            public_key.encode(encode),
            backend=default_backend()
        )
        return public



if __name__ == '__main__':
    password = 'abcd'
    k1 = Ed25519.create(password)
    k2 = Ed25519.create(password)
    print(
        'Test #1: ',
        Ed25519.public_key_enc(
            Ed25519.get_public(k1)
        ) \
            == \
        Ed25519.public_key_enc(
            Ed25519.get_public(k2)
        )
    )
    print(
        'Test #2: ',
        Ed25519.private_key_enc(k1) \
            == \
        Ed25519.private_key_enc(k2)
    )

    k1 = Ed25519.private_key_enc(k1)
    k2 = Ed25519.private_key_dec(k1)
    k2 = Ed25519.private_key_enc(k2)
    print(
        'Test #3: ',
        k1 \
            == \
        k2
    )

    k1 = Ed25519.create(password)
    k1_pub = Ed25519.public_key_enc(
            Ed25519.get_public(k1)
        )
    print(
        'Test #4: ',
        k1_pub \
            == Ed25519.public_key_enc(
            Ed25519.public_key_dec(k1_pub)
        )
    )
