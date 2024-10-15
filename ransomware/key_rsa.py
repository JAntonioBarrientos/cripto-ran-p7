from Crypto.PublicKey import RSA

# Generar un par de claves RSA (clave pública y privada)
key = RSA.generate(2048)

# Guardar la clave privada
with open("private_rsa_key.pem", 'wb') as f:
    f.write(key.export_key())

# Guardar la clave pública
with open("public_rsa_key.pem", 'wb') as f:
    f.write(key.publickey().export_key())
