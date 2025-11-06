"""
pw_manager_cli.py
Command-line password manager compatible with the encrypted .pwm database format.
"""

import os
import sys
import json
import time
import select
import base64
import random
import string
import secrets
import platform
import argparse
import threading
from time import sleep
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

import pyperclip

# ---------- Constants ----------
SALT_SIZE = 16


# ---------- Encryption ----------
def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    pw = password.encode("utf-8")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(pw))


def encrypt_db(data: dict, password: str, salt: bytes) -> bytes:
    key = derive_key(password, salt)
    f = Fernet(key)
    return f.encrypt(json.dumps(data).encode("utf-8"))


def decrypt_db(token: bytes, password: str, salt: bytes) -> dict:
    key = derive_key(password, salt)
    f = Fernet(key)
    plaintext = f.decrypt(token)
    return json.loads(plaintext.decode("utf-8"))


def save_file(path: str, db: dict, password: str) -> None:
    salt = secrets.token_bytes(SALT_SIZE)
    encrypted = encrypt_db(db, password, salt)
    with open(path, "wb") as f:
        f.write(salt + encrypted)


def load_file(path: str, password: str) -> dict:
    with open(path, "rb") as f:
        raw = f.read()
    salt, token = raw[:SALT_SIZE], raw[SALT_SIZE:]
    return decrypt_db(token, password, salt)



# ---------- CLI App ----------
class PasswordManagerCLI:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.db = {}
        self.master_password = None
        self.last_action_time = time.time()
        self.lock_timeout = 150  # seconds (2m30s)
        self.locked = False
        self.lock_event = threading.Event()

    def reset_inactivity_timer(self):
        self.last_action_time = time.time()

    def timed_input(self, prompt=">>> "):
        """Regular input with inactivity auto-lock."""
        timeout = self.lock_timeout
        start = time.time()

        print(prompt, end="", flush=True)
        buf = ""
        while True:
            if platform.system() == "Windows":
                import msvcrt
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    if ch in ("\r", "\n"):
                        print()
                        self.reset_inactivity_timer()
                        return buf.strip()
                    elif ch == "\b":
                        buf = buf[:-1]
                        sys.stdout.write("\b \b")
                        sys.stdout.flush()
                    else:
                        buf += ch
                        sys.stdout.write(ch)
                        sys.stdout.flush()
            else:
                if sys.stdin in select.select([sys.stdin], [], [], 1)[0]:
                    line = sys.stdin.readline()
                    self.reset_inactivity_timer()
                    return line.strip()

            # timeout check
            if time.time() - start > timeout:
                if not self.locked:
                    self.auto_lock()
                else:
                    continue
                self.reset_inactivity_timer()
                start = time.time()
                # after unlock, restart prompt
                print(prompt, end="", flush=True)
                buf = ""


    def timed_getpass(self, prompt="Password: "):
        """Hidden password input with inactivity auto-lock."""
        timeout = self.lock_timeout
        start = time.time()
        buf = ""

        if platform.system() == "Windows":
            import msvcrt
            sys.stdout.write(prompt)
            sys.stdout.flush()
            while True:
                if msvcrt.kbhit():
                    ch = msvcrt.getwch()
                    if ch in ("\r", "\n"):
                        print()
                        self.reset_inactivity_timer()
                        return buf
                    elif ch == "\b":
                        buf = buf[:-1]
                    else:
                        buf += ch
                # timeout
                if time.time() - start > timeout:
                    if not self.locked:
                        print("\n")
                        self.auto_lock()
                    else:
                        continue
                    self.reset_inactivity_timer()
                    start = time.time()
                    sys.stdout.write(prompt)
                    sys.stdout.flush()
                    buf = ""
        else:
            import termios, tty
            sys.stdout.write(prompt)
            sys.stdout.flush()
            fd = sys.stdin.fileno()
            old_settings = termios.tcgetattr(fd)
            try:
                tty.setraw(fd)
                while True:
                    r, _, _ = select.select([sys.stdin], [], [], 1)
                    if r:
                        ch = sys.stdin.read(1)
                        if ch in ("\r", "\n"):
                            print()
                            self.reset_inactivity_timer()
                            return buf
                        elif ch == "\x7f":  # backspace
                            buf = buf[:-1]
                        else:
                            buf += ch
                    if time.time() - start > timeout:
                        if not self.locked:
                            print()
                            self.auto_lock()
                            sys.stdout.write(prompt)
                        else: 
                            continue
                        self.reset_inactivity_timer()
                        start = time.time()
                        sys.stdout.flush()
                        buf = ""
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


    def prompt_master_password(self):
        print("--- Enter Master Password ---")
        pw = self.timed_getpass(">>> ")
        self.master_password = pw

    def load_db(self):
        print("\033[2J\033[H", end="") # Clear screen
        print("----- Loading Database -----")
        if not os.path.exists(self.db_path):
            print(f"No existing database found at {self.db_path}.")
            choice = self.timed_input("Create new database? (y/n): ").strip().lower()
            if choice != "y":
                exit()
            pw1 = self.timed_getpass("Set master password: ")
            pw2 = self.timed_getpass("Confirm master password: ")
            if pw1 != pw2:
                print("Passwords do not match. Exiting.")
                self.line_break()
                sleep(2)
                exit(1)
            self.master_password = pw1
            self.db = {}
            save_file(self.db_path, self.db, pw1)
            print("New database created.")
            self.line_break()
            sleep(1)
        else:
            if not self.master_password:
                print("\033[2J\033[H", end="") # Clear screen
                self.prompt_master_password()
            try:
                self.db = load_file(self.db_path, self.master_password)
                print("Database unlocked successfully.")
                self.line_break()
                sleep(1)
            except (InvalidToken, ValueError):
                print("Invalid password or corrupted file.")
                self.line_break()
                sleep(2)
                exit(1)

    def save(self):
        print("\033[2J\033[H", end="") # Clear screen
        print("------ Saving Database -----")
        save_file(self.db_path, self.db, self.master_password)
        print("Database saved.")
        self.line_break()
        sleep(1)
    
    def auto_lock(self):
        if self.locked:
            return
        self.locked = True
        self.save()
        print("\033[2J\033[H", end="")
        print("------- Password Manager -------")
        print("Session locked due to inactivity.")
        while True:
            self.prompt_master_password()
            try:
                self.db = load_file(self.db_path, self.master_password)
                self.locked = False
                self.reset_inactivity_timer()
                print("Database unlocked.")
                self.line_break()
                sleep(1)
                print("\033[2J\033[H", end="") # Clear screen
                print("------- Password Manager -------")
                self.list_entries()
                print("""
- Please choose an option: -
1. Add entry
2. Edit entry
3. Delete entry
4. Copy username
5. Copy password
6. Save
7. Exit
""")
                break
            except (InvalidToken, ValueError):
                print("Invalid password. Try again.")

    def Yes_No(self, ch):
        if ch == "y":
            return True
        elif ch == "n":
            return False
        elif ch == "":
            return True
        else:
            return False

    def generate_password(self, length=12, use_symbols=True, use_numbers=True, use_capitals=True):
        chars = string.ascii_lowercase
        chars += string.ascii_uppercase if use_capitals else ""
        chars += string.digits if use_numbers else ""
        chars += "!#$%&*+,-.=?@_~" if use_symbols else ""
        return ''.join(random.choice(chars) for _ in range(length))

    def random_password(self):
        inputStr = ""
        inputStr = self.timed_input("Length (6-64): ").strip()
        self.reset_inactivity_timer()
        try:
            return self.generate_password(length=int(inputStr))
        except ValueError:
            print("please use numbers.")
    def line_break(self):
        print("----------------------------")

    def list_entries(self):
        print("------ Stored Entries ------")
        if not self.db:
            print("No entries in database.")
            self.line_break()
            return
        for i, (eid, rec) in enumerate(
            sorted(self.db.items(), key=lambda kv: kv[1].get("label", "").lower()), start=1
        ):
            print(f"[{i}] {rec.get('label','')} (username: {rec.get('username','')})")
        self.line_break()

    def add_entry(self):
        print("\033[2J\033[H", end="") # Clear screen
        self.list_entries()
        print("------- Add New Entry ------")
        label = self.timed_input("Label: ").strip()
        self.reset_inactivity_timer()
        username = self.timed_input("Username/Email: ").strip()
        self.reset_inactivity_timer()
        inputStr = self.timed_input("Generate random password? (y/n): ").strip().lower()
        self.reset_inactivity_timer()
        if inputStr == "y":
            password = self.random_password()
            print(f"Generated password.")
        else:
            password = self.timed_getpass("Password: ").strip()
            self.reset_inactivity_timer()
        if not label or not username or not password:
            print("All fields required.")
            self.line_break()
            sleep(2)
            return
        eid = secrets.token_hex(8)
        self.db[eid] = {"label": label, "username": username, "password": password}
        print(f"Added entry '{label}'.")
        self.line_break()
        sleep(1)

    def edit_entry(self):
        print("\033[2J\033[H", end="") # Clear screen
        self.list_entries()
        print("-------- Edit Entry --------")
        try:
            idx = int(self.timed_input("Select entry number to edit: ")) - 1
            self.reset_inactivity_timer()
        except ValueError:
            print("Invalid input.")
            self.line_break()
            sleep(2)
            return
        if idx < 0 or idx >= len(self.db):
            print("Invalid entry number.")
            self.line_break()
            sleep(2)
            return
        key = list(sorted(self.db.items(), key=lambda kv: kv[1]["label"].lower()))[idx][0]
        rec = self.db[key]

        print("Press Enter to keep current values.")
        label = self.timed_input(f"Label [{rec['label']}]: ").strip() or rec["label"]
        self.reset_inactivity_timer()
        username = self.timed_input(f"Username [{rec['username']}]: ").strip() or rec["username"]
        self.reset_inactivity_timer()
        password = self.timed_getpass("Password (leave blank to keep current): ").strip() or rec["password"]
        self.reset_inactivity_timer()
        self.db[key] = {"label": label, "username": username, "password": password}
        print(f"Updated '{label}'.")
        self.line_break()
        sleep(1)

    def delete_entry(self):
        print("\033[2J\033[H", end="") # Clear screen
        self.list_entries()
        print("------- Delete Entry -------")
        try:
            idx = int(self.timed_input("Select entry number to delete: ")) - 1
            self.reset_inactivity_timer()
        except ValueError:
            print("Invalid input.")
            self.line_break()
            sleep(2)
            return
        if idx < 0 or idx >= len(self.db):
            print("Invalid entry number.")
            self.line_break()
            sleep(2)
            return
        key = list(sorted(self.db.items(), key=lambda kv: kv[1]["label"].lower()))[idx][0]
        rec = self.db[key]
        confirm = self.timed_input(f"Delete '{rec['label']}'? (y/n): ").strip().lower()
        if confirm == "y":
            del self.db[key]
            print(f"Deleted '{rec['label']}'.")
        else:
            print("Deletion cancelled.")
        self.line_break()
        sleep(1)

    def copy_password(self):
        print("\033[2J\033[H", end="") # Clear screen
        self.list_entries()
        print("------- Copy Password ------")
        try:
            idx = int(self.timed_input("Select entry number to copy password: ")) - 1
            self.reset_inactivity_timer()
        except ValueError:
            print("Invalid input.")
            self.line_break()
            sleep(2)
            return
        if idx < 0 or idx >= len(self.db):
            print("Invalid entry number.")
            self.line_break()
            sleep(2)
            return
        key = list(sorted(self.db.items(), key=lambda kv: kv[1]["label"].lower()))[idx][0]
        pw = self.db[key]["password"]
        pyperclip.copy(pw)
        print("Password copied to clipboard (clears manually).")
        self.line_break()
        sleep(1)

    def copy_username(self):
        print("\033[2J\033[H", end="") # Clear screen
        self.list_entries()
        print("------- Copy Username ------")
        try:
            idx = int(self.timed_input("Select entry number to copy username: ")) - 1
            self.reset_inactivity_timer()
        except ValueError:
            print("Invalid input.")
            self.line_break()
            sleep(2)
            return
        if idx < 0 or idx >= len(self.db):
            print("Invalid entry number.")
            self.line_break()
            sleep(2)
            return
        key = list(sorted(self.db.items(), key=lambda kv: kv[1]["label"].lower()))[idx][0]
        uname = self.db[key]["username"]
        pyperclip.copy(uname)
        print("Username copied to clipboard.")
        print("-----------------------------")
        sleep(1)

    def menu(self):
        while True:

            if self.lock_event.is_set():
                self.lock_event.clear()
                self.auto_lock()

            print("\033[2J\033[H", end="")
            print("------- Password Manager -------")
            self.list_entries()
            print("""
- Please choose an option: -
1. Add entry
2. Edit entry
3. Delete entry
4. Copy username
5. Copy password
6. Save
7. Exit
""")
            choice = self.timed_input("Select option: ").strip()
            self.reset_inactivity_timer()
            if choice == "1":
                self.add_entry()
            elif choice == "2":
                self.edit_entry()
            elif choice == "3":
                self.delete_entry()
            elif choice == "4":
                self.copy_username()
            elif choice == "5":
                self.copy_password()
            elif choice == "6":
                self.save()
            elif choice == "7":
                print("Goodbye.")
                sleep(1)
                print("\033[2J\033[H", end="") # Clear screen
                break
            else:
                print("Invalid option.")


def main():
    parser = argparse.ArgumentParser(description="Encrypted password manager CLI")
    parser.add_argument("db_path", help="Path to encrypted .pwm database file")
    args = parser.parse_args()

    cli = PasswordManagerCLI(args.db_path)
    cli.load_db()
    cli.menu()


if __name__ == "__main__":

    main()
