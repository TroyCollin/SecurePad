# SecurePad Studio 3

A VS Code-inspired Linux editor with local encrypted documents and a separate GnuPG/OpenPGP workflow.

## What's new in v3
- VS Code-style workspace layout with file explorer, tabbed editor and security dock
- Line numbers and a lightweight minimap (View → Toggle Minimap)
- Syntax highlighting for Python, shell, SQL and common configuration/text formats
- Find/replace, word wrap, read-only mode, dark theme and status bar
- Session-only reuse of encrypted-document passphrase/key-file settings, held in process memory and never written to settings
- Recovery Manager to inspect, restore into a new tab, or delete encrypted recovery snapshots
- AES-256-GCM encrypted `.spad` documents using scrypt-derived keys
- Optional separate key files and GnuPG/OpenPGP CLI and GUI workflows
- Password lock, inactivity auto-lock, encrypted recovery snapshots and local file backups

## Install on Ubuntu
```bash
sudo apt update
sudo apt install python3-venv python3-pip gnupg
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python securepad.py
```

## CLI examples
```bash
python securepad.py --help
python securepad.py --version
python securepad.py encrypt notes.txt -o notes.spad
python securepad.py decrypt notes.spad -o notes.txt
python securepad.py gpg-encrypt notes.txt -o notes.gpg --recipient recipient@example.com
python securepad.py gpg-decrypt notes.gpg -o notes.txt
```

Passphrases are prompted interactively rather than accepted as command-line arguments.

## Security notes
- The custom `.spad` format is SecurePad-specific and is **not EncryptPad-compatible**. OpenPGP is a separate interoperability path via GnuPG.
- This project has not undergone a professional security audit. Test with non-sensitive data before relying on it.
- Session-retained passphrases and key-file bytes remain in process memory until the app exits or the tab is closed.
- The editor lock is a convenience barrier, not protection against malware or another process running as the same user; it does not wipe plaintext from memory.
- Recovery snapshots are encrypted with a random key stored in the same user account. They help against casual inspection but do not protect against account compromise.
- Plaintext file backups may be created under `~/.local/share/securepad-studio/file-backups` when overwriting plaintext files.
- The GUI changes have been syntax-checked and the CLI smoke-tested, but the GUI has not been fully desktop-tested on every Linux environment.
