# cripto-ran-p7

Para crear el entorno virtual, ejecutar el siguiente comando:

```bash
python -m venv venv
```

Para activar el entorno virtual, en Windows:

```bash
venv\Scripts\activate
```

Instalar las dependencias:

```bash
pip install -r requirements.txt
```

Para crear el ejecutable, ejecutar el siguiente comando:

```bash
pyinstaller --onefile --add-data "public_key.pem;." --add-data "fondo.jpeg;." main.py
```