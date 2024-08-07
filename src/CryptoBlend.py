import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def generate_key(algo):
    if algo == 'AES':
        return get_random_bytes(16)  # 16 bytes for AES-128
    elif algo == 'DES':
        return get_random_bytes(8)  # 8 bytes for DES

def encrypt_aes(text):
    key = generate_key('AES')
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct, base64.b64encode(key).decode('utf-8')

def decrypt_aes(ciphertext, key):
    iv = base64.b64decode(ciphertext[:24])
    ct = base64.b64decode(ciphertext[24:])
    key = base64.b64decode(key)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def encrypt_des(text):
    key = generate_key('DES')
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode('utf-8'), DES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct, base64.b64encode(key).decode('utf-8')

def decrypt_des(ciphertext, key):
    iv = base64.b64decode(ciphertext[:12])
    ct = base64.b64decode(ciphertext[12:])
    key = base64.b64decode(key)
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), DES.block_size)
    return pt.decode('utf-8')

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_rsa(text, public_key):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    ciphertext = cipher.encrypt(text.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_rsa(ciphertext, private_key):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    plaintext = cipher.decrypt(base64.b64decode(ciphertext))
    return plaintext.decode('utf-8')

def encrypt_text():
    text = input_text.get("1.0", tk.END).strip()
    algo = algo_combobox.get()
    
    try:
        if algo == 'AES':
            encrypted_text, key = encrypt_aes(text)
        elif algo == 'DES':
            encrypted_text, key = encrypt_des(text)
        elif algo == 'RSA':
            private_key, public_key = generate_rsa_keys()
            encrypted_text = encrypt_rsa(text, public_key)
            output_text.delete("1.0", tk.END)
            output_text.insert(tk.END, f"Encrypted Text: {encrypted_text}\nPublic Key: {public_key.decode('utf-8')}\nPrivate Key: {private_key.decode('utf-8')}")
            return
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, f"Encrypted Text: {encrypted_text}\nKey: {key}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_text():
    data = input_text.get("1.0", tk.END).strip().split("\n")
    if len(data) < 2 or not data[0].startswith("Encrypted Text: ") or (not data[1].startswith("Key: ") and not (data[1].startswith("Public Key: ") and data[2].startswith("Private Key: "))):
        messagebox.showerror("Error", "Input format is incorrect. Please provide 'Encrypted Text' followed by 'Key' or 'Public Key' and 'Private Key'.")
        return

    ciphertext = data[0][15:].strip()
    algo = algo_combobox.get()

    try:
        if algo == 'AES':
            key = data[1][5:].strip()
            decrypted_text = decrypt_aes(ciphertext, key)
        elif algo == 'DES':
            key = data[1][5:].strip()
            decrypted_text = decrypt_des(ciphertext, key)
        elif algo == 'RSA':
            private_key = "\n".join(data[2:]).replace("Private Key: ", "").strip()
            decrypted_text = decrypt_rsa(ciphertext, private_key)
        output_text.delete("1.0", tk.END)
        output_text.insert(tk.END, decrypted_text)
    except Exception as e:
        messagebox.showerror("Error", str(e))

app = tk.Tk()
app.title("Text Encryption Tool")

tk.Label(app, text="Input Text").grid(row=0, column=0, padx=10, pady=10)
input_text = tk.Text(app, height=10, width=50)
input_text.grid(row=0, column=1, padx=10, pady=10)

tk.Label(app, text="Algorithm").grid(row=1, column=0, padx=10, pady=10)
algo_combobox = ttk.Combobox(app, values=['AES', 'DES', 'RSA'])
algo_combobox.grid(row=1, column=1, padx=10, pady=10)
algo_combobox.current(0)

encrypt_button = tk.Button(app, text="Encrypt", command=encrypt_text)
encrypt_button.grid(row=2, column=0, padx=10, pady=10)

decrypt_button = tk.Button(app, text="Decrypt", command=decrypt_text)
decrypt_button.grid(row=2, column=1, padx=10, pady=10)

tk.Label(app, text="Output Text").grid(row=3, column=0, padx=10, pady=10)
output_text = tk.Text(app, height=10, width=50)
output_text.grid(row=3, column=1, padx=10, pady=10)

app.mainloop()
