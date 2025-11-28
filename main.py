"""
pw_manager_cli.py
Command-line password manager compatible with the encrypted .pwm database format.
Modular rewrite for maintainability.
"""
import argparse

from lib.cli import CLI
from lib.password_manager import PasswordManager

# ---------- Main ----------
def main():
    parser = argparse.ArgumentParser(description="Encrypted password manager CLI")
    parser.add_argument("db_path", help="Path to encrypted .pwm database file")
    args = parser.parse_args()
    try:
        cli = CLI()
        pm = PasswordManager(args.db_path, cli)
        pm.load_config()
        pm.load_db()
        pm.menu()
    except KeyboardInterrupt:
        pm.closing_sequence()

if __name__ == "__main__":
    main()