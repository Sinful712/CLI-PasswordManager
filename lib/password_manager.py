import os
import configparser
import string
import random
import secrets
from time import sleep
import pyperclip
from cryptography.fernet import InvalidToken

from .tui import set_title, goodbye
from .cli import CLI
from .database import Database
from .encryption import Encryption


# ---------- Main Application ----------
class PasswordManager:
    def __init__(self, db_path: str, cli: CLI):
        self.db_path = db_path
        self.db = Database()
        self.master_password = None
        self.cli = cli
        self.encryption = Encryption()

    def load_config(self):
        config = configparser.ConfigParser()
        default_path = os.path.join(os.getcwd(), "config.ini")
        if not os.path.exists(default_path):
            self.cli.print_message("No config.ini found, using default settings.")
            return
        config.read(default_path)
        try:
            if "AutoLockSettings" in config:
                lock = config["AutoLockSettings"]
                self.cli.autolock_enabled = lock.getboolean("Autolock", fallback=self.cli.autolock_enabled)
                self.cli.lock_timeout = lock.getint("AutolockTime", fallback=self.cli.lock_timeout)
            if "TextColor" in config:
                colorconf = config["TextColor"]
                self.cli.is_colored = colorconf.getboolean("is_colored", fallback=self.cli.is_colored)
            if "Entries" in config:
                print_entries = config["Entries"]
                self.cli.always_print_entries = print_entries.getboolean("PrintEntries", fallback=self.cli.always_print_entries)
        except Exception as e:
            self.cli.print_message(f"Error reading config.ini: {e}")
            self.cli.print_message("Falling back to defaults.")

    def prompt_master_password(self):
        self.cli.center_text("Enter Master Password", "-")
        pw, timed_out = self.cli.timed_getpass(">>> ")
        if timed_out:
            self.auto_lock()
            return
        self.master_password = pw.strip()
        return pw

    def create_database_path(self):
        folder_path = os.path.dirname(self.db_path)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)

    def load_db(self):
        self.cli.clear_screen()
        self.cli.print_message("----- Loading Database -----")
        if not os.path.exists(self.db_path):
            self.cli.print_message(f"No existing database found at {self.db_path}.")
            CreateDB, _ = self.cli.timed_input("Create new database? (y/n): ")
            if not self.cli.yes_no(CreateDB.strip().lower()):
                exit()
            self.create_database_path()
            pw1, _ = self.cli.timed_getpass("Set master password: ")
            pw1 = pw1.strip()
            self.cli.reset_inactivity_timer()
            pw2, _ = self.cli.timed_getpass("Confirm master password: ")
            pw2 = pw2.strip()
            self.cli.reset_inactivity_timer()
            if pw1 != pw2:
                self.cli.print_message("Passwords do not match. Exiting.")
                self.cli.line_break()
                sleep(2)
                exit(1)
            self.master_password = pw1
            self.encryption.save_file(self.db_path, self.db.to_dict(), pw1)
            self.cli.print_message("New database created.")
            self.cli.line_break()
            sleep(1)
        else:
            set_title("PWM - " + os.path.basename(self.db_path).removesuffix(".pwm"))
            while True:
                self.cli.clear_screen()
                self.cli.center_text("Unlock Database", "-")
                self.cli.print_message(f"Current Database: {os.path.basename(self.db_path)}")
                self.prompt_master_password()
                try:
                    data = self.encryption.load_file(self.db_path, self.master_password)
                    self.db = Database.from_dict(data)
                    self.cli.print_message("Database unlocked successfully.")
                    self.cli.line_break()
                    sleep(1)
                    break
                except (InvalidToken, ValueError):
                    self.cli.print_message("Invalid password or corrupted file.")
                    self.cli.line_break()
                    sleep(2)
                    continue

    def save_db(self):
        self.cli.clear_screen()
        self.cli.center_text("Saving Database", "-")
        self.encryption.save_file(self.db_path, self.db.to_dict(), self.master_password)
        self.cli.print_message("Database saved.")
        self.cli.line_break()
        sleep(1)

    def generate_password(self, length=12, use_symbols=True, use_numbers=True, use_capitals=True):
        chars = string.ascii_lowercase
        chars += string.ascii_uppercase if use_capitals else ""
        chars += string.digits if use_numbers else ""
        chars += "!#$%&*+,-.=?@_~" if use_symbols else ""
        return ''.join(random.choice(chars) for _ in range(length))

    def random_password(self):
        while True:
            input_str, _ = self.cli.timed_input("Length (10-64): ")
            self.cli.reset_inactivity_timer()
            try:
                if 10 < int(input_str) < 65:
                    return self.generate_password(length=int(input_str))
                else:
                    self.cli.print_message("Please specify a number in the range of 10-64.")
                    sleep(1)
                    continue
            except ValueError:
                self.cli.print_message("Please use numbers.")
                sleep(1)
                continue

    def list_entries(self, print_index=True, line_break=False, user_check=False, group=None):
        if user_check:
            self.cli.clear_screen()
        self.cli.center_text("Stored Entries", "-")
        entries = self.db.entries
        if not entries:
            self.cli.print_message("No entries in database.")
            if line_break:
                self.cli.line_break()
            return
        
        if group and group != "All":
            entries = self.db.entries_in_group(group)

        for i, (eid, rec) in enumerate(
            sorted(entries.items(), key=lambda kv: kv[1].get("label", "").lower()), start=1):
            entry_num = f"[{i}]" if print_index else ""
            group_str = f"[{rec.get('group', 'Ungrouped')}]"
            text = f"{rec.get('label','')} (username: {rec.get('username','')}) {group_str}"
            if print_index:
                print(entry_num, end="")
                self.cli.center_text(text, " ", len(entry_num))
            else:
                self.cli.center_text(text)
        if line_break:
            self.cli.line_break()
        if user_check:
            self.cli.debug_break()

    def list_all_grouped(self, pause=False):
        self.cli.clear_screen()
        self.cli.center_text("All Entries", "-")
        groups = self.db.list_groups()
        entries = self.db.entries
        if not entries:
            self.cli.print_message("No entries found.")
            self.cli.line_break()
            if pause:
                self.cli.debug_break()
            return

        for g in sorted(groups):
            group_entries = {
                eid: rec for eid, rec in entries.items()
                if rec.get("group", "Ungrouped") == g
            }
            if not group_entries:
                continue

            print()
            self.cli.center_text(f"{g}:", " ")
            for eid, rec in sorted(group_entries.items(),
                                   key=lambda kv: kv[1]["label"].lower()):
                print(f"- {rec['label']} ({rec['username']})")

        print()
        self.cli.line_break()
        if pause:
            self.cli.debug_break()

    def show_groups(self):
        self.cli.clear_screen()
        self.cli.center_text("Groups", "-")
        for g in sorted(self.db.list_groups()):
            print(" -", g)
        self.cli.line_break()
        self.cli.debug_break()

    def rename_group(self):
        self.cli.clear_screen()
        self.cli.center_text("Groups", "-")
        groups = [g for g in self.db.list_groups() if g != "Ungrouped"]  # Exclude Ungrouped for safety
        if not groups:
            self.cli.print_message("No groups to rename.")
            self.cli.line_break()
            self.cli.debug_break()
            return
        for g in groups:
            print(f"- {g}")
        self.cli.line_break()
        print()
        old_name, _ = self.cli.timed_input("Group to rename: ")
        old_name = old_name.strip()
        if not old_name or old_name not in groups:
            self.cli.print_message("Invalid group name.")
            sleep(1)
            return
        new_name, _ = self.cli.timed_input("New group name: ")
        new_name = new_name.strip()
        if not new_name:
            self.cli.print_message("New name cannot be empty.")
            sleep(1)
            return
        if self.db.rename_group(old_name, new_name):
            self.cli.print_message(f"Renamed '{old_name}' to '{new_name}' and updated all related entries/subgroups.")
        else:
            self.cli.print_message("Rename failed (group not found or name conflict).")
        sleep(1)

    def add_entry(self):
        self.cli.clear_screen()
        if self.cli.always_print_entries:
            self.list_entries(False)
        self.cli.center_text("Add New Entry", "-")
        label, _ = self.cli.timed_input("Label: ")
        label = label.strip()
        self.cli.reset_inactivity_timer()
        username, _ = self.cli.timed_input("Username/Email: ")
        username = username.strip()
        self.cli.reset_inactivity_timer()
        GenPass, _ = self.cli.timed_input("Generate random password? (Y/n): ")
        if self.cli.yes_no(GenPass.strip().lower()):
            password = self.random_password()
            self.cli.center_text("Generated password.")
        else:
            password, _ = self.cli.timed_getpass("Password: ")
            password = password.strip()
            self.cli.reset_inactivity_timer()
        if not label or not username or not password:
            self.cli.print_message("All fields required.")
            self.cli.line_break()
            sleep(2)
            return
        
        groups = self.db.list_groups()
        if groups:
            print()
            self.cli.center_text("Available Groups", "-")
            for g in groups:
                print(f" - {g}")
        group_choice, _ = self.cli.timed_input("Assign to group (leave blank for 'Ungrouped'): ")
        group_choice = group_choice.strip()
        group_choice = group_choice if group_choice else "Ungrouped"
        self.db.create_group(group_choice)

        eid = secrets.token_hex(8)
        self.db.entries[eid] = {
            "label": label, 
            "username": username, 
            "password": password,
            "group": group_choice
        }
        self.cli.center_text(f"Added entry '{label}' to group '{group_choice}'.")
        self.cli.line_break()
        sleep(1)

    def edit_entry(self):
        self.cli.clear_screen()
        self.list_entries()
        self.cli.center_text("Edit Entry", "-")
        try:
            EntryNumber, _ = self.cli.timed_input("Select entry number to edit: ")
            idx = int(EntryNumber) - 1
            self.cli.reset_inactivity_timer()
        except ValueError:
            self.cli.print_message("Invalid input.")
            self.cli.line_break()
            sleep(2)
            return

        entries = sorted(self.db.entries.items(), key=lambda kv: kv[1]["label"].lower())
        if idx < 0 or idx >= len(entries):
            self.cli.print_message("Invalid entry number.")
            self.cli.line_break()
            sleep(2)
            return

        key, rec = entries[idx]

        self.cli.print_message("Press Enter to keep current values.")
        label, _ = self.cli.timed_input(f"Label [{rec['label']}]: ") or rec["label"]
        label = label.strip()
        self.cli.reset_inactivity_timer()
        username, _ = self.cli.timed_input(f"Username [{rec['username']}]: ") or rec["username"]
        username = username.strip()
        self.cli.reset_inactivity_timer()
        password, _ = self.cli.timed_getpass("Password (leave blank to keep current): ") or rec["password"]
        password = password.strip()
        self.cli.reset_inactivity_timer()

        # Handle group assignment
        groups = self.db.list_groups()
        if groups:
            self.cli.print_message("")
            self.cli.center_text("Available Groups", "-")
            for g in groups:
                print(f" - {g}")
        group_choice, _ = self.cli.timed_input(f"Assign to group (leave blank for current '{rec.get('group', 'Ungrouped')}'): ")
        group_choice = group_choice.strip()
        group_choice = group_choice if group_choice else rec.get("group", "Ungrouped")
        self.db.create_group(group_choice)

        # Update the entry
        self.db.entries[key] = {
            "label": label,
            "username": username,
            "password": password,
            "group": group_choice
        }
        self.cli.center_text(f"Updated entry '{label}' in group '{group_choice}'.")
        self.cli.line_break()
        sleep(1)

    def delete_entry(self):
        self.cli.clear_screen()
        self.list_entries()
        self.cli.center_text("Delete Entry", "-")
        try:
            EntryNumber, _ = self.cli.timed_input("Select entry number to delete: ")
            idx = int(EntryNumber) - 1
            self.cli.reset_inactivity_timer()
        except ValueError:
            self.cli.print_message("Invalid input.")
            self.cli.line_break()
            sleep(2)
            return

        entries = sorted(self.db.entries.items(), key=lambda kv: kv[1]["label"].lower())
        if idx < 0 or idx >= len(entries):
            self.cli.print_message("Invalid entry number.")
            self.cli.line_break()
            sleep(2)
            return

        key, rec = entries[idx]
        ConfirmDelete, _ = self.cli.timed_input(f"Delete '{rec['label']}'? (y/N): ")
        if self.cli.yes_no(ConfirmDelete.strip().lower(), flipped=True):
            del self.db.entries[key]
            self.cli.print_message(f"Deleted '{rec['label']}'.")
        else:
            self.cli.print_message("Deletion cancelled.")
        self.cli.line_break()
        sleep(1)

    def copy_password(self):
        self.cli.clear_screen()
        self.list_entries()
        self.cli.center_text("Copy Password", "-")
        try:
            EntryNumber, _ = self.cli.timed_input("Select entry number to copy password: ")
            idx = int(EntryNumber) - 1
            self.cli.reset_inactivity_timer()
        except ValueError:
            self.cli.print_message("Invalid input.")
            self.cli.line_break()
            sleep(2)
            return

        entries = sorted(self.db.entries.items(), key=lambda kv: kv[1]["label"].lower())
        if idx < 0 or idx >= len(entries):
            self.cli.print_message("Invalid entry number.")
            self.cli.line_break()
            sleep(2)
            return

        key, rec = entries[idx]
        pyperclip.copy(rec["password"])
        self.cli.print_message("Password copied to clipboard (clears manually).")
        self.cli.line_break()
        sleep(1)

    def copy_username(self):
        self.cli.clear_screen()
        self.list_entries()
        self.cli.center_text("Copy Username", "-")
        try:
            EntryNumber, _ = self.cli.timed_input("Select entry number to copy username: ")
            idx = int(EntryNumber) - 1
            self.cli.reset_inactivity_timer()
        except ValueError:
            self.cli.print_message("Invalid input.")
            self.cli.line_break()
            sleep(2)
            return

        entries = sorted(self.db.entries.items(), key=lambda kv: kv[1]["label"].lower())
        if idx < 0 or idx >= len(entries):
            self.cli.print_message("Invalid entry number.")
            self.cli.line_break()
            sleep(2)
            return

        key, rec = entries[idx]
        pyperclip.copy(rec["username"])
        self.cli.print_message("Username copied to clipboard.")
        self.cli.line_break()
        sleep(1)

    def management_menu(self):
        while True:
            self.cli.clear_screen()
            self.cli.center_text("Management Menu", "-")
            print("""1. Add entry
2. Edit entry
3. Delete entry
4. Create group
5. Rename group
6. Delete group
7. Back
""")
            choice, _ = self.cli.timed_input("Select option: ")
            self.cli.reset_inactivity_timer()

            if choice == "1":
                self.add_entry()
            elif choice == "2":
                self.edit_entry()
            elif choice == "3":
                self.delete_entry()
            elif choice == "4":
                name, _ = self.cli.timed_input("Group name: ")
                if name:
                    self.db.create_group(name)
                    self.cli.print_message(f"Created: {name}")
                    sleep(1)
            elif choice == "5":
                self.rename_group()
            elif choice == "6":
                self.cli.clear_screen()
                self.cli.center_text("Groups", "-")
                groups = self.db.list_groups()
                for i in groups:
                    if i != "Ungrouped":
                        print(f"- {i}")
                self.cli.line_break()
                print()
                name, _ = self.cli.timed_input("Group to delete: ")
                if name:
                    self.db.delete_group(name)
                    self.cli.print_message("Deleted and reassigned entries.")
                    sleep(1)
            elif choice == "7":
                return
            else:
                self.cli.print_message("Invalid option.")
                sleep(1)

    def about(self):
        self.cli.clear_screen()
        self.cli.print_message("Version: 1.0")
        self.cli.print_message("Built on Python Version: 3.13")
        self.cli.print_message("Created by: Jesse Edwards (AKA:Sinful712)")
        self.cli.line_break()
        self.cli.timed_input("Press Enter to continue...")

    def closing_sequence(self):
        if self.master_password:
            self.cli.clear_screen()
            SaveDB, _ = self.cli.timed_input("Do you want to save the database before exiting? (Y/n): ")
            if self.cli.yes_no(SaveDB.strip().lower()):
                self.save_db()
        goodbye()
        sleep(1)
        self.cli.clear_screen()
        print("\033[0m", end="")
        exit(1)

    def menu(self):
        while True:
            self.cli.clear_screen()
            if self.cli.always_print_entries:
                self.list_all_grouped()

            self.cli.center_text("Please select an option", "-")
            print("""1. Copy password
2. Copy username
3. List all
4. List groups
5. Management
6. Save
7. About
Type (8 / Exit / Quit) or ctrl+c to leave.
""")

            choice, timed_out = self.cli.timed_input("Select option: ")
            if timed_out:
                self.auto_lock()
                continue  # After unlocking, restart the menu
            choice = choice.strip()
            self.cli.reset_inactivity_timer()

            if choice == "1":
                self.copy_password()
            elif choice == "2":
                self.copy_username()
            elif choice == "3":
                self.list_all_grouped(True)
            elif choice == "4":
                self.show_groups()
            elif choice == "5":
                self.management_menu()
            elif choice == "6":
                self.save_db()
            elif choice == "7":
                self.about()
            elif choice == "8" or choice.lower() in ("exit", "quit"):
                self.closing_sequence()
            else:
                self.cli.print_message("Invalid option.")
                sleep(1)

    def auto_lock(self):
        if self.cli.locked:
            return
        self.cli.locked = True
        
        try:
            self.save_db()
        except:
            self.cli.print_message("""Due to inactivity at startup,
the database could not be loaded.
Exiting...""")
            self.cli.line_break()
            sleep(2)
            exit(1)
        
        self.db = Database()  # Clear database
        self.master_password = None
        while True:
            self.cli.clear_screen()
            self.cli.center_text("Password Manager", "=")
            self.cli.print_message("Session locked due to inactivity.")
            self.cli.print_message(f"Current Database: {os.path.basename(self.db_path)}")
            pw = self.prompt_master_password()
            if pw is None:  # Timeout occurred
                continue
            try:
                data = self.encryption.load_file(self.db_path, self.master_password)
                self.db = Database.from_dict(data)
                self.cli.locked = False
                self.cli.reset_inactivity_timer()
                self.cli.print_message("Database unlocked.")
                self.cli.line_break()
                sleep(1)
                break
            except (InvalidToken, ValueError):
                self.cli.print_message("Invalid password. Try again.")

