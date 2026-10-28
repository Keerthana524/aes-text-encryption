"""
main.py
-------
Command-line interface for the Secure Text Encryption and Decryption System.

Run interactively:
    python main.py

Or use direct commands:
    python main.py encrypt -m "Meet at 5 PM"
    python main.py decrypt -t "<encrypted text>"
    python main.py encrypt-file -i secret.txt -o secret.enc
    python main.py decrypt-file -i secret.enc -o recovered.txt
"""

import argparse
import getpass
import sys

from aes_cipher import DecryptionError, decrypt, encrypt

BANNER = r"""
=======================================================
   SECURE TEXT ENCRYPTION & DECRYPTION SYSTEM (AES-256)
=======================================================
"""


def ask_password(confirm: bool = False) -> str:
    """Read a password without echoing it to the screen."""
    while True:
        pwd = getpass.getpass("Enter password: ")
        if not pwd:
            print("  Password cannot be empty. Try again.")
            continue
        if confirm and getpass.getpass("Confirm password: ") != pwd:
            print("  Passwords do not match. Try again.")
            continue
        return pwd


def read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def write_file(path: str, content: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


# ---------------------------------------------------------------- interactive


def interactive() -> None:
    print(BANNER)
    menu = (
        "1. Encrypt a message\n"
        "2. Decrypt a message\n"
        "3. Encrypt a text file\n"
        "4. Decrypt a text file\n"
        "5. Exit"
    )
    while True:
        print("\n" + menu)
        choice = input("\nChoose an option (1-5): ").strip()

        try:
            if choice == "1":
                message = input("Enter the message to encrypt: ")
                result = encrypt(message, ask_password(confirm=True))
                print("\n[+] Encrypted text (share this):\n" + result)

            elif choice == "2":
                token = input("Paste the encrypted text: ")
                result = decrypt(token, ask_password())
                print("\n[+] Decrypted message:\n" + result)

            elif choice == "3":
                src = input("Path of file to encrypt: ").strip()
                dst = input("Save encrypted file as: ").strip()
                write_file(dst, encrypt(read_file(src), ask_password(confirm=True)))
                print(f"\n[+] Encrypted file saved to {dst}")

            elif choice == "4":
                src = input("Path of encrypted file: ").strip()
                dst = input("Save decrypted file as: ").strip()
                write_file(dst, decrypt(read_file(src), ask_password()))
                print(f"\n[+] Decrypted file saved to {dst}")

            elif choice == "5":
                print("Goodbye!")
                return

            else:
                print("  Invalid choice. Please enter 1-5.")

        except DecryptionError as err:
            print(f"\n[!] Decryption failed: {err}")
        except FileNotFoundError as err:
            print(f"\n[!] File not found: {err.filename}")
        except ValueError as err:
            print(f"\n[!] {err}")


# ---------------------------------------------------------------- commands


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt confidential text using AES-256-GCM."
    )
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("encrypt", help="Encrypt a message")
    p.add_argument("-m", "--message", required=True, help="Message to encrypt")

    p = sub.add_parser("decrypt", help="Decrypt a message")
    p.add_argument("-t", "--token", required=True, help="Encrypted text to decrypt")

    p = sub.add_parser("encrypt-file", help="Encrypt a text file")
    p.add_argument("-i", "--input", required=True)
    p.add_argument("-o", "--output", required=True)

    p = sub.add_parser("decrypt-file", help="Decrypt an encrypted file")
    p.add_argument("-i", "--input", required=True)
    p.add_argument("-o", "--output", required=True)

    return parser


def run_command(args: argparse.Namespace) -> int:
    try:
        if args.command == "encrypt":
            print(encrypt(args.message, ask_password(confirm=True)))
        elif args.command == "decrypt":
            print(decrypt(args.token, ask_password()))
        elif args.command == "encrypt-file":
            write_file(args.output, encrypt(read_file(args.input), ask_password(confirm=True)))
            print(f"Encrypted file saved to {args.output}")
        elif args.command == "decrypt-file":
            write_file(args.output, decrypt(read_file(args.input), ask_password()))
            print(f"Decrypted file saved to {args.output}")
    except DecryptionError as err:
        print(f"Decryption failed: {err}", file=sys.stderr)
        return 1
    except FileNotFoundError as err:
        print(f"File not found: {err.filename}", file=sys.stderr)
        return 1
    return 0


def main() -> int:
    args = build_parser().parse_args()
    if args.command is None:
        interactive()
        return 0
    return run_command(args)


if __name__ == "__main__":
    sys.exit(main())
