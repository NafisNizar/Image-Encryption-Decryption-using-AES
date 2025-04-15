import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from PIL import Image
import os

# Constants
KEY = b'ThisIsASecretKey'  # 16 bytes for AES-128
BLOCK_SIZE = AES.block_size

def pad(data):
    padding_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_len]) * padding_len

def unpad(data):
    return data[:-data[-1]]

def encrypt_image(file_path):
    try:
        with open(file_path, 'rb') as f:
            image_data = f.read()

        cipher = AES.new(KEY, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(image_data))
        encrypted_file = file_path + ".enc"

        with open(encrypted_file, 'wb') as f:
            f.write(cipher.iv + ciphertext)

        messagebox.showinfo("Encryption", f"Image encrypted and saved as:\n{encrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed:\n{e}")

def decrypt_image(file_path):
    try:
        with open(file_path, 'rb') as f:
            iv = f.read(16)
            ciphertext = f.read()

        cipher = AES.new(KEY, AES.MODE_CBC, iv=iv)
        decrypted_data = unpad(cipher.decrypt(ciphertext))

        original_filename = file_path.replace('.enc', '_decrypted.png')

        with open(original_filename, 'wb') as f:
            f.write(decrypted_data)

        messagebox.showinfo("Decryption", f"Image decrypted and saved as:\n{original_filename}")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed:\n{e}")

def open_encrypt():
    file_path = filedialog.askopenfilename(
        title="Select Image to Encrypt",
        filetypes=[
            ("Image files", "*.png *.jpg *.jpeg *.bmp"),
            ("All files", "*.*")
        ]
    )
    if file_path:
        print("Selected file for encryption:", file_path)
        encrypt_image(file_path)
    else:
        print("No file selected for encryption.")

def open_decrypt():
    file_path = filedialog.askopenfilename(
        title="Select Encrypted File",
        filetypes=[("Encrypted Files", "*.enc"), ("All files", "*.*")]
    )
    if file_path:
        print("Selected file for decryption:", file_path)
        decrypt_image(file_path)
    else:
        print("No file selected for decryption.")

# Tkinter GUI
root = tk.Tk()
root.title("AES Image Encryptor/Decryptor")
root.geometry("300x200")
root.resizable(False, False)

title_label = tk.Label(root, text="AES Image Encryptor", font=("Arial", 14, "bold"))
title_label.pack(pady=10)

encrypt_btn = tk.Button(root, text="Encrypt Image", command=open_encrypt, width=25, bg="#4CAF50", fg="white")
encrypt_btn.pack(pady=10)

decrypt_btn = tk.Button(root, text="Decrypt Image", command=open_decrypt, width=25, bg="#2196F3", fg="white")
decrypt_btn.pack(pady=10)

root.mainloop()
