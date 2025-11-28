# encryption_module.py
"""
File encryption and decryption module using Fernet (symmetric encryption)
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

class FileEncryption:
    def __init__(self, password="default_secure_password"):
        """
        Initialize encryption with a password-based key
        """
        self.password = password.encode()
        self.salt = b'shareit_p2p_salt'  # In production, use random salt and store it
        
    def _generate_key(self):
        """Generate encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,  # Change 'salt' to 'self.salt'
            iterations=100000
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.password))
        return key
    
    def encrypt_file(self, input_file_path, output_file_path=None):
        """
        Encrypt a file and save it
        Returns: path to encrypted file
        """
        try:
            # Generate encryption key
            key = self._generate_key()
            fernet = Fernet(key)
            
            # Read original file
            with open(input_file_path, 'rb') as file:
                original_data = file.read()
            
            # Encrypt data
            encrypted_data = fernet.encrypt(original_data)
            
            # Determine output path
            if output_file_path is None:
                output_file_path = input_file_path + '.encrypted'
            
            # Write encrypted file
            with open(output_file_path, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)
            
            return output_file_path
            
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")
    
    def decrypt_file(self, encrypted_file_path, output_file_path=None):
        """
        Decrypt a file and save it
        Returns: path to decrypted file
        """
        try:
            # Generate decryption key
            key = self._generate_key()
            fernet = Fernet(key)
            
            # Read encrypted file
            with open(encrypted_file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()
            
            # Decrypt data
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Determine output path
            if output_file_path is None:
                if encrypted_file_path.endswith('.encrypted'):
                    output_file_path = encrypted_file_path[:-10]  # Remove .encrypted
                else:
                    output_file_path = encrypted_file_path + '.decrypted'
            
            # Write decrypted file
            with open(output_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            
            return output_file_path
            
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")
    
    def encrypt_data(self, data):
        """Encrypt raw bytes data"""
        try:
            key = self._generate_key()
            fernet = Fernet(key)
            return fernet.encrypt(data)
        except Exception as e:
            raise Exception(f"Data encryption failed: {str(e)}")
    
    def decrypt_data(self, encrypted_data):
        """Decrypt raw bytes data"""
        try:
            key = self._generate_key()
            fernet = Fernet(key)
            return fernet.decrypt(encrypted_data)
        except Exception as e:
            raise Exception(f"Data decryption failed: {str(e)}")

# Utility functions for easy access
def get_encryptor(password=None):
    """Get an encryption instance"""
    if password:
        return FileEncryption(password)
    return FileEncryption()