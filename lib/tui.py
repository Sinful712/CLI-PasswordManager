import os
import sys
import shutil
import platform
from time import sleep

# ---------- Terminal Utilities ----------
def goodbye():
    cols, rows = shutil.get_terminal_size()
    os.system('cls' if os.name=='nt' else 'clear')
    pad_top = "\n" * (rows // 2)
    print(pad_top + "Goodbye".center(cols))
    sleep(1)
    os.system('cls' if os.name=='nt' else 'clear')

def set_title(title: str):
    if platform.system() == "Windows":
        os.system(f"title {title}")
    else:
        sys.stdout.write(f"\x1b]2;{title}\x07")
        sys.stdout.flush()