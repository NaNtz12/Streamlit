from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from pathlib import Path

PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"

def npm_20221310071_load_or_create_keys():
    if Path(PRIVATE_KEY_FILE).exists() and Path(PUBLIC_KEY_FILE).exists():
        with open(PRIVATE_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        with open(PUBLIC_KEY_FILE, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        with open(PRIVATE_KEY_FILE, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        with open(PUBLIC_KEY_FILE, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

    return private_key, public_key
