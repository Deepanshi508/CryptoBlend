# Cryptoblend

**Cryptoblend** is a graphical text encryption tool built with Tkinter. It supports AES, DES, and RSA encryption algorithms, providing an easy-to-use interface for encrypting and decrypting text.

## Features

- **AES Encryption**: Secure text encryption with AES-128.
- **DES Encryption**: Basic text encryption with DES.
- **RSA Encryption**: Encrypt text using RSA with key pair generation.
- **Graphical Interface**: User-friendly GUI created with Tkinter.

## Installation

To get started with Cryptoblend, follow these steps:

1. **Clone the Repository**

   Open your terminal or command prompt and clone the repository:
   ```bash
   git clone https://github.com/Deepanshi508/CryptoBlend.git

2. **Navigate to the Project Directory**

Change your directory to the cloned project folder:
cd cryptoblend

3. **Install Required Packages**

Install the necessary Python packages using pip:

pip install pycryptodome

**Usage**
Run the Application

Open your preferred code editor or IDE (such as VSCode or PyCharm), and open the project directory.

Locate the main_code.py file in the src folder and run it. You can usually run the script by right-clicking on the file and selecting "Run," or by using the run command in your editor.

Using the GUI

Input Text: Enter the text you want to encrypt or decrypt in the "Input Text" box.
Algorithm: Select the encryption algorithm (AES, DES, or RSA) from the dropdown menu.
Encrypt/Decrypt: Click the "Encrypt" or "Decrypt" button to perform the corresponding action.
For AES and DES, a key will be displayed along with the encrypted text. For RSA, both a public key and a private key will be provided along with the encrypted text.

Code Overview
The project consists of a main Python script (src/main_code.py) that provides a graphical interface for encryption and decryption operations. It utilizes the pycryptodome library for cryptographic functions.

Key Functions
generate_key(algo): Generates a key for AES or DES encryption.
encrypt_aes(text): Encrypts text using AES.
decrypt_aes(ciphertext, key): Decrypts AES-encrypted text.
encrypt_des(text): Encrypts text using DES.
decrypt_des(ciphertext, key): Decrypts DES-encrypted text.
generate_rsa_keys(): Generates RSA key pair.
encrypt_rsa(text, public_key): Encrypts text using RSA.
decrypt_rsa(ciphertext, private_key): Decrypts RSA-encrypted text.
