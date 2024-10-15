import os
import zipfile

# Obtener el directorio "Documents" del usuario
user_profile = os.environ['USERPROFILE']
documents_dir = os.path.join(user_profile, 'Documents')

# Extensiones que se desean comprimir
extensions = ['.docx', '.xlsx', '.pdf', '.jpeg', '.jpg', '.txt']

# Crear un archivo zip
zip_file_path = os.path.join(documents_dir, 'archivos_comprimidos.zip')
with zipfile.ZipFile(zip_file_path, 'w') as zipf:
    for foldername, subfolders, filenames in os.walk(documents_dir):
        for filename in filenames:
            # Comprobar si el archivo tiene una de las extensiones especificadas
            if any(filename.endswith(ext) for ext in extensions):
                file_path = os.path.join(foldername, filename)
                zipf.write(file_path, os.path.relpath(file_path, documents_dir))

print(f'Archivos comprimidos en {zip_file_path}')
