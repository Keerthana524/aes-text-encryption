# 🔐 Secure Text Encryption and Decryption System Using AES

A Python application that **encrypts and decrypts confidential messages and text files using AES-256** to maintain data confidentiality.

## 🎯 Objective

To encrypt and decrypt confidential messages using the Advanced Encryption Standard (AES) so that only someone with the correct password can read them.

## ✨ Features

- **AES-256-GCM** encryption, the current industry standard
- **Password-based keys** using PBKDF2-HMAC-SHA256 (200,000 iterations)
- **Random salt and nonce** for every message, so the same text never produces the same ciphertext
- **Tamper detection**: GCM's authentication tag rejects modified data or a wrong password
- Encrypt / decrypt **messages** and **text files**
- **Interactive menu** plus direct command-line commands
- Passwords are typed hidden (never shown on screen)
- Output is **Base64 text**, so it is easy to copy, email or store
- Unit tests included

## 🛠️ Tech Stack

| Component | Used |
|---|---|
| Language | Python 3.8+ |
| Library | [`cryptography`](https://cryptography.io/) |
| Cipher | AES-256 in GCM mode |
| Key derivation | PBKDF2-HMAC-SHA256 |

## 📁 Project Structure

```
aes-text-encryption/
├── aes_cipher.py          # Core AES encryption & decryption logic
├── main.py                # Command-line interface (menu + commands)
├── tests/
│   └── test_aes_cipher.py # Unit tests
├── sample_message.txt     # Sample file to try file encryption
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

## 🚀 Installation

```bash
git clone https://github.com/<your-username>/aes-text-encryption.git
cd aes-text-encryption
pip install -r requirements.txt
```

## ▶️ Usage

### Interactive mode

```bash
python main.py
```

```
=======================================================
   SECURE TEXT ENCRYPTION & DECRYPTION SYSTEM (AES-256)
=======================================================

1. Encrypt a message
2. Decrypt a message
3. Encrypt a text file
4. Decrypt a text file
5. Exit

Choose an option (1-5): 1
Enter the message to encrypt: Meet at 5 PM
Enter password:
Confirm password:

[+] Encrypted text (share this):
q3Jm0d...Xk2A==
```

### Direct commands

```bash
# Encrypt / decrypt a message
python main.py encrypt -m "Meet at 5 PM"
python main.py decrypt -t "q3Jm0d...Xk2A=="

# Encrypt / decrypt a file
python main.py encrypt-file -i sample_message.txt -o secret.enc
python main.py decrypt-file -i secret.enc -o recovered.txt
```

## ⚙️ How It Works

**Encryption**
1. A random 16-byte **salt** is generated.
2. The password and salt go through **PBKDF2** to derive a 256-bit AES key.
3. A random 12-byte **nonce** is generated.
4. The message is encrypted with **AES-256-GCM**, which also produces a 16-byte authentication tag.
5. `salt + nonce + ciphertext + tag` is Base64-encoded and returned.

**Decryption**
1. The Base64 text is decoded and split into salt, nonce and ciphertext.
2. The same key is re-derived from the password and salt.
3. AES-GCM decrypts the data and verifies the tag. If the password is wrong or the data was altered, decryption is **rejected**.

```
Plaintext + Password
        │
        ▼
 PBKDF2 (salt) ──► 256-bit key
        │
        ▼
 AES-256-GCM (nonce) ──► Ciphertext + Auth Tag
        │
        ▼
 Base64( salt | nonce | ciphertext | tag )
```

## 🧪 Running Tests

```bash
python -m unittest discover tests -v
```

Tests cover round-trip encryption, Unicode text, randomness of output, wrong-password rejection, tamper detection and invalid input.

## 🔒 Why AES-GCM?

- **AES** is a symmetric block cipher standardised by NIST and used worldwide (HTTPS, Wi-Fi, disk encryption).
- **GCM mode** provides both **confidentiality** (data is unreadable) and **integrity** (any change is detected), unlike older modes such as ECB or CBC.
- **PBKDF2** with many iterations slows down brute-force attacks on the password.

## 📌 Future Enhancements

- Graphical user interface (Tkinter / web)
- Encryption of images and binary files
- Public-key (RSA) exchange of the AES key

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
