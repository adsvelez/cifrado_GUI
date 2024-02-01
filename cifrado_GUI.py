import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def key_derivation(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=100000,
        length=32,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def cifrar():
    ruta_archivo = filedialog.askopenfilename(title="Seleccionar archivo a cifrar")
    texto_ingresado = password.get()

    if ruta_archivo and texto_ingresado != "":
        salt = os.urandom(16)
        key = key_derivation(texto_ingresado, salt)
        iv = os.urandom(16)

        with open(ruta_archivo, 'rb') as file:
            plaintext = file.read()

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        with open(ruta_archivo + ".enc", 'wb') as encrypted_file:
            encrypted_file.write(salt + iv + ciphertext)
            password.delete(0, tk.END)
            resul = "Archivo cifrado con exito: " + ruta_archivo + ".enc"
            resultado.config(text=resul)

    else:       
        password.delete(0, tk.END)
        resul = "Error al cifrar el archivo "
        resultado.config(text=resul)

def descifrar():
    ruta_archivo = filedialog.askopenfilename(title="Seleccionar archivo a descifrar")
    texto_ingresado = password.get()
    if ruta_archivo and texto_ingresado != "":     
        with open(ruta_archivo, 'rb') as encrypted_file:
            data = encrypted_file.read()
        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]
        key = key_derivation(texto_ingresado, salt)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        original_file_path = ruta_archivo[:-4]
        with open(original_file_path, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)
            password.delete(0, tk.END)
            resul = "Archivo descifrado con exito: " + original_file_path
            resultado.config(text=resul)
    else:
        password.delete(0, tk.END)
        resul = "Error al descifrar el archivo "
        resultado.config(text=resul)

def mostrar_ayuda():
    mensaje_ayuda = "1. Seleccione un password para cifrar o el password para descifrar el archivo. \n 2. De click en el botón Cifrar o Descifrar según el caso. \n 3. El archivo cifrado o Descifrado se almacenará en la misma ruta."

    messagebox.showinfo("Ayuda", mensaje_ayuda)

def salir_aplicacion():
    root.destroy()
###########
root = tk.Tk()
root.title("Mini cifrado")
###########

lista_menu = tk.Menu(root)
root.config(menu=lista_menu)

label_password = tk.Label(root, text="Password:")
password = tk.Entry(root, width=20)

cifrar = tk.Button(root, text="Cifrar", command=cifrar)
descifrar = tk.Button(root, text="Descifrar", command=descifrar)

resultado = tk.Label(root, text="")

btn_salir = tk.Button(root, text="Salir", command=salir_aplicacion)

###########

ayuda = tk.Menu(lista_menu, tearoff=0)
lista_menu.add_command(label="Ayuda", command=mostrar_ayuda)


label_password.grid(row=1, column=0, pady=10, padx=10)
password.grid(row=1, column=1, pady=10, padx=10)

cifrar.grid(row=2, column=0, pady=10, padx=10)
descifrar.grid(row=2, column=1, pady=10, padx=10)

resultado.grid(row=3,column=1, pady=0, padx=0)

btn_salir.grid(row=4, column=0, pady=10, padx=10)

root.mainloop()