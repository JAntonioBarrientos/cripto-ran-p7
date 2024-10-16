"""
Este programa se encarga de descifrar archivos previamente cifrados con AES. Para ello, utiliza una clave AES 
descifrada con RSA y la clave privada correspondiente. El programa está diseñado para ser empaquetado con PyInstaller.

Funciones incluidas:
- Lectura de clave privada RSA desde un archivo
- Descifrado de clave AES cifrada con RSA
- Descifrado de archivos utilizando la clave AES
- Procesamiento de todos los archivos en el directorio Documentos
"""

import os
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
import sys

def leer_clave_privada():
    """
    Lee la clave privada desde el archivo 'private_key.pem'.

    Retorna:
        rsa.RSAPrivateKey: Clave privada RSA.
    
    Lógica:
    El programa detecta si está empaquetado con PyInstaller y ajusta la ruta de acceso a 'private_key.pem' en 
    consecuencia. La clave privada es leída desde el archivo y cargada utilizando la biblioteca cryptography. 
    Se devuelve como un objeto RSA para ser utilizado en el descifrado.
    """
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    ruta_clave_privada = os.path.join(base_path, 'private_key.pem')

    with open(ruta_clave_privada, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,  
            backend=default_backend()
        )

    return private_key

def descifrar_clave_aes(clave_aes_cifrada, private_key):
    """
    Descifra la clave AES utilizando la clave privada RSA.

    Args:
        clave_aes_cifrada (str): Clave AES cifrada en formato Base64.
        private_key (rsa.RSAPrivateKey): Clave privada RSA para descifrar la clave AES.
    
    Retorna:
        bytes: Clave AES descifrada.
    
    Lógica:
    La clave AES cifrada es primero decodificada desde Base64. Luego, se utiliza la clave privada RSA para descifrarla 
    usando el esquema de padding OAEP, que emplea SHA-256 como función hash.
    """
    clave_aes_cifrada_bytes = base64.b64decode(clave_aes_cifrada)

    clave_aes = private_key.decrypt(
        clave_aes_cifrada_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return clave_aes

def descifrar_archivo_aes(archivo, clave_aes):
    """
    Descifra un archivo utilizando la clave AES en modo CBC.

    Args:
        archivo (str): Ruta al archivo cifrado con la extensión '.owo'.
        clave_aes (bytes): Clave AES para descifrar el archivo.
    
    Lógica:
    El archivo cifrado se abre y se extrae el vector de inicialización (IV) del primer bloque de 16 bytes. 
    A continuación, el resto del archivo (datos cifrados) es descifrado utilizando la clave AES en modo CBC 
    y el IV leído. El padding es removido al final y el archivo descifrado se guarda reemplazando la extensión '.owo'.
    """
    with open(archivo, 'rb') as f:
        iv = f.read(16)  # Leer el IV del archivo cifrado
        datos_cifrados = f.read()  # Leer los datos cifrados

    cipher = AES.new(clave_aes, AES.MODE_CBC, iv)
    datos_descifrados = unpad(cipher.decrypt(datos_cifrados), AES.block_size)

    archivo_descifrado = archivo.replace('.owo', '')
    with open(archivo_descifrado, 'wb') as f:
        f.write(datos_descifrados)

def descifrar_archivos_documentos():
    """
    Descifra todos los archivos con la extensión '.owo' en la carpeta Documentos del usuario.

    Lógica:
    La función principal del programa comienza leyendo la clave privada desde el archivo 'private_key.pem'. 
    Luego, se lee la clave AES cifrada desde un archivo 'clave_aes_cifrada.lol', la cual es descifrada usando 
    la clave privada. Finalmente, se recorren todos los archivos en la carpeta Documentos y aquellos que tengan 
    la extensión '.owo' son descifrados utilizando la clave AES.
    """
    user_profile = os.environ['USERPROFILE']
    documents_dir = os.path.join(user_profile, 'Documents')

    private_key = leer_clave_privada()

    with open(os.path.join(documents_dir, 'clave_aes_cifrada.lol'), 'r') as f:
        clave_aes_cifrada = f.read()

    clave_aes = descifrar_clave_aes(clave_aes_cifrada, private_key)

    for foldername, subfolders, filenames in os.walk(documents_dir):
        for filename in filenames:
            if filename.endswith('.owo'):
                file_path = os.path.join(foldername, filename)
                descifrar_archivo_aes(file_path, clave_aes)
                print(f'Archivo descifrado: {file_path}')

# Ejecutar la función principal
descifrar_archivos_documentos()
