# HoboFrancs OneDrop

**First created. First recorded.**

This drop contains a working:
- `hobo` CLI (stamp/commit/verify/publish + flags + private + sealed)
- GitHub Pages verifier (`/verify/`)
- Public ledger (`/verify/ledger.json`)
- Issue template + GitHub Action to append stamps to ledger

## Quick start
```bash
python -m hobo stamp my_work.png
python -m hobo publish my_work.png --repo OWNER/REPO --token YOUR_TOKEN
python -m hobo publish my_work.png --private --sealed --passphrase "StrongPass"
python -m hobo verify --sealed certificates/my_work.hobo.json.sealed --file my_work.png --passphrase "StrongPass"
```
