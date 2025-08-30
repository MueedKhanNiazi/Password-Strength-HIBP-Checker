This is a simple app I made that checks if your password is strong and if it's been leaked in any Data breaches

What it does

- Tells you how strong your password is (weak, medium, strong, etc.)
- Shows how long it would take someone to crack it
- Checks if your password was part of any big data breaches
- Gives you tips to make your password better
- Has a simple window interface, no command line stuff

  your password stays on your computer, it doesn't get sent anywhere.

## Files in here

- `main.py` - starts the app
- `UI.py` - the window and buttons stuff  
- `security.py` - does the actual password checking

## Making it into an .exe file

If you want to make it into a proper Windows program:

```bash
pip install pyinstaller
pyinstaller --onefile --windowed main.py
```

This makes a single .exe file you can run without needing Python installed.

