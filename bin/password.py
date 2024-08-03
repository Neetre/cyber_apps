from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization


class Password:

    @staticmethod
    def generate(password):
        key = Password.generate_key()
        Password.save_key(key)
        enc_pwd = Password.encrypt_password(password, key)
        return enc_pwd
    
    @staticmethod
    def generate_key():
        return Fernet.generate_key()

    @staticmethod
    def encrypt_password(password, key):
        f = Fernet(key)
        encrypted_password = f.encrypt(password.encode("utf-8"))
        return encrypted_password
    
    @staticmethod
    def decrypt_password(enc_password, key):
        f = Fernet(key)
        dec_password = f.decrypt(enc_password).decode("utf-8")
        return dec_password
    
    @staticmethod
    def save_key(key):
        with open('secret.key', 'wb') as key_file:
            key_file.write(key)
            
    @staticmethod
    def load_key():
        return open('secret.key', 'rb').read()
    
    @staticmethod
    def is_secure(password):
        pass