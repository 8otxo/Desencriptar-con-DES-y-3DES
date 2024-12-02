from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad
import hashlib

def generate_key_from_password(password, length):
    """
    Genera una clave de longitud específica desde una contraseña utilizando SHA-256.

    Args:
        password (str): Contraseña ingresada por el usuario.
        length (int): Longitud deseada de la clave.

    Returns:
        bytes: Clave generada de longitud `length`.
    """
    key = hashlib.sha256(password.encode()).digest()
    return key[:length]

def des_encrypt(key, plaintext):
    """
    Cifra un texto usando DES.

    Args:
        key (bytes): Clave de 8 bytes para DES.
        plaintext (str): Texto plano a cifrar.

    Returns:
        bytes: Texto cifrado.
    """
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode('utf-8'), DES.block_size))

def des_decrypt(key, ciphertext):
    """
    Descifra un texto cifrado usando DES.

    Args:
        key (bytes): Clave de 8 bytes para DES.
        ciphertext (bytes): Texto cifrado.

    Returns:
        str: Texto descifrado.
    """
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES.block_size).decode('utf-8')

def triple_des_encrypt(key, plaintext):
    """
    Cifra un texto usando 3DES.

    Args:
        key (bytes): Clave de 16 o 24 bytes para 3DES.
        plaintext (str): Texto plano a cifrar.

    Returns:
        bytes: Texto cifrado.
    """
    cipher = DES3.new(key, DES3.MODE_ECB)
    return cipher.encrypt(pad(plaintext.encode('utf-8'), DES3.block_size))

def triple_des_decrypt(key, ciphertext):
    """
    Descifra un texto cifrado usando 3DES.

    Args:
        key (bytes): Clave de 16 o 24 bytes para 3DES.
        ciphertext (bytes): Texto cifrado.

    Returns:
        str: Texto descifrado.
    """
    cipher = DES3.new(key, DES3.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size).decode('utf-8')

if __name__ == "__main__":
    print("Herramienta de cifrado/descifrado con DES y 3DES")
    print("Seleccione una opción:")
    print("1. Cifrar con DES")
    print("2. Descifrar con DES")
    print("3. Cifrar con 3DES")
    print("4. Descifrar con 3DES")
    opcion = input("Opción: ")

    if opcion in ['1', '2']:
        password = input("Ingrese una contraseña para generar la clave (mínimo 8 caracteres): ")
        while len(password) < 8:
            print("La contraseña debe tener al menos 8 caracteres.")
            password = input("Ingrese una contraseña: ")
        des_key = generate_key_from_password(password, 8)

    elif opcion in ['3', '4']:
        password = input("Ingrese una contraseña para generar la clave (mínimo 16 caracteres): ")
        while len(password) < 16:
            print("La contraseña debe tener al menos 16 caracteres.")
            password = input("Ingrese una contraseña: ")
        triple_des_key = generate_key_from_password(password, 16)

    if opcion == '1':  # Cifrar con DES
        plaintext = input("Ingrese el texto a cifrar: ")
        encrypted = des_encrypt(des_key, plaintext)
        print(f"Texto cifrado (DES): {encrypted.hex()}")

    elif opcion == '2':  # Descifrar con DES
        ciphertext = bytes.fromhex(input("Ingrese el texto cifrado en formato hexadecimal: "))
        try:
            decrypted = des_decrypt(des_key, ciphertext)
            print(f"Texto descifrado (DES): {decrypted}")
        except ValueError:
            print("Error: el texto cifrado o la clave son incorrectos.")

    elif opcion == '3':  # Cifrar con 3DES
        plaintext = input("Ingrese el texto a cifrar: ")
        encrypted = triple_des_encrypt(triple_des_key, plaintext)
        print(f"Texto cifrado (3DES): {encrypted.hex()}")

    elif opcion == '4':  # Descifrar con 3DES
        ciphertext = bytes.fromhex(input("Ingrese el texto cifrado en formato hexadecimal: "))
        try:
            decrypted = triple_des_decrypt(triple_des_key, ciphertext)
            print(f"Texto descifrado (3DES): {decrypted}")
        except ValueError:
            print("Error: el texto cifrado o la clave son incorrectos.")
    else:
        print("Opción no válida.")
