# CLI-PasswordManager

Command-line password manager compatible with the encrypted .pwm database format.
Works well on a usb stick.


## Requirements
```bash
python.exe -m pip install cryptography pyperclip
```

## Usage
In the same directory as the script
```bash
python pw_manager-cli.py "path\to\file.pwm" 
```
If the file doesnt exist it prompts the user and then creates the file.

Then Prompts the user for a __Master Password__

In the future i will be building it and release packaged releases for each operating system: Windows, Linux, macOS.
