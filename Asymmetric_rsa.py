from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

class asymmetric:
    def generating_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,  # 2048
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def storing_keys(self,private_key,public_key):
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open('private_key.pem', 'wb') as f:
            f.write(pem)

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open('public_key.pem', 'wb') as f:
            f.write(pem)

    def Reading_keys(self, private_key, public_key):
        with open("private_key.pem", "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        with open("public_key.pem", "rb") as key_file:
            public_key = key_file.read()
            key_file.close()

        return private_key, public_key

    def read_public_key_server(self, text):
        public_key = serialization.load_pem_public_key(
            text,
            backend=default_backend()
        )
        return public_key

    def encryption(self, public_key, message):
        encrypted = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted

    def decryption(self, private_key, encry):
        original_message = private_key.decrypt(
            encry,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_message
