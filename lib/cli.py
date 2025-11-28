import os
import sys
import shutil
import platform
import time
import threading
import select
from getpass import getpass


# ---------- CLI Module ----------
class CLI:
    def __init__(self, autolock_enabled=True, lock_timeout=150, is_colored=True, always_print_entries=False):
        self.autolock_enabled = autolock_enabled
        self.lock_timeout = lock_timeout
        self.is_colored = is_colored
        self.always_print_entries = always_print_entries
        self.last_action_time = time.time()
        self.locked = False
        self.lock_event = threading.Event()
        self.color_terminal()

    def color_terminal(self):
        if self.is_colored:
            print("\033[1;92m", end="")  # Turn all text green
        else:
            print("\033[0m", end="")  # Turn all text back to normal

    def reset_inactivity_timer(self):
        self.last_action_time = time.time()

    def timed_input(self, prompt=">>> "):
        if not self.autolock_enabled:
            return input(prompt), False  # No timeout, so timed_out=False

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
                        return buf.strip(), False
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
                    return line.strip(), False

            if time.time() - start > timeout:
                print()  # Newline after timeout
                return "", True  # Return empty string and timed_out=True

    def timed_getpass(self, prompt="Password: "):
        if not self.autolock_enabled:
            return getpass(prompt), False

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
                        return buf, False
                    elif ch == "\b":
                        buf = buf[:-1]
                    else:
                        buf += ch
                if time.time() - start > timeout:
                    print()
                    return "", True
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
                            return buf, False
                        elif ch == "\x7f":  # Backspace
                            buf = buf[:-1]
                        else:
                            buf += ch
                    if time.time() - start > timeout:
                        print()
                        return "", True
            finally:
                termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def auto_lock(self):
        if self.locked:
            return
        self.locked = True
        print("Session locked due to inactivity.")

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def center_text(self, text: str, fill_char: str = " ", sub_prefix: int = 0, sub_suffix: int = 0):
        width = shutil.get_terminal_size().columns
        total_padding = max(width - len(text), 0)
        left = (total_padding // 2)
        right = (total_padding - left)
        print(fill_char * (left - sub_prefix) + text + fill_char * (right - sub_suffix))

    def line_break(self):
        width = shutil.get_terminal_size().columns
        print("-" * width)

    def print_message(self, message: str):
        print(message)

    def debug_break(self):
        self.timed_input("Press 'Enter' to continue...")

    def yes_no(self, ch, flipped=False):
        if not flipped:
            return False if ch.lower() == "n" else True
        else:
            return True if ch.lower() == "y" else False