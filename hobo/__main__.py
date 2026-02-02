#!/usr/bin/env python3
import sys, hashlib, json, subprocess, datetime, os, platform, base64, urllib.request, urllib.error
from pathlib import Path

BASE = Path.cwd()
CERTS = BASE / "certificates"
CERTS.mkdir(exist_ok=True)

PRINCIPLE = "First created. First recorded."

def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def utc_now() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def has_hfr() -> bool:
    try:
        return int(os.getenv("HFR_TOKEN_BALANCE", "0")) > 0
    except ValueError:
        return False

def parse_flags(argv):
    positional = []
    flags = {}
    it = iter(argv)
    for a in it:
        if a.startswith("--"):
            k = a[2:]
            if k in ["dry-run","commit","yes","private","auto","sealed"]:
                flags[k] = True
            else:
                try:
                    flags[k] = next(it)
                except StopIteration:
                    print(f"Missing value for --{k}")
                    sys.exit(2)
        else:
            positional.append(a)
    return positional, flags

def run_git(args):
    try:
        subprocess.run(["git"] + args, check=True)
    except FileNotFoundError:
        print("Git not found. Install git or use `stamp` (no git needed).")
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print("Git error:", e)
        sys.exit(1)

def git_commit_hash() -> str:
    return subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()

def ensure_repo_initialized():
    if not (BASE / ".git").exists():
        run_git(["init"])
    gi = BASE / ".gitignore"
    if not gi.exists():
        gi.write_text("*.pyc\n__pycache__/\n*.log\n.env\n*.keystore\n*.jks\n*.p12\n*.pem\n")
        run_git(["add", ".gitignore"])

def write_cert(path: Path, cert: dict) -> Path:
    out = CERTS / f"{path.stem}.hobo.json"
    out.write_text(json.dumps(cert, indent=2))
    return out

def build_cert(path: Path, file_hash: str, tier: str, git_commit: str | None, verify_url: str):
    cert = {
        "schema": "hobofrancs.hobo_entry.v1",
        "type": "HOBO_ENTRY",
        "principle": PRINCIPLE,
        "file": path.name,
        "file_hash": file_hash,
        "timestamp": utc_now(),
        "tier": tier,
        "origin": {
            "platform": platform.system().lower(),
            "app": "hobo-cli",
            "device_binding": "optional-nonpii"
        },
        "verification": {
            "method": "sha256_hash_match",
            "voluntary": True,
            "verify_url": verify_url
        },
        "disclaimer": {
            "non_authoritative": True,
            "no_ownership_claim": True,
            "no_legal_enforcement": True
        }
    }
    if git_commit:
        cert["git_commit"] = git_commit
        cert["network"] = "git"
    else:
        cert["network"] = "local"
    return cert

def print_help():
    print("HoboFrancs CLI — " + PRINCIPLE)
    print("")
    print("Commands:")
    print("  init")
    print("  stamp <file>")
    print("  commit <file>")
    print("  verify <file>")
    print("  verify --sealed <cert.sealed> --file <file> --passphrase <pass>")
    print("  publish <file> [--auto] [--repo OWNER/REPO] [--token TOKEN] [--verify-url URL] [--title TITLE]")
    print("               [--dry-run] [--commit] [--tier HOBO|HFR] [--private] [--sealed] [--passphrase PASS]")
    print("  unseal <cert.sealed> --passphrase <pass>")
    print("")
    print("Env vars (optional):")
    print("  GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN, HOBO_VERIFY_URL, HOBO_PRIVATE_PASSPHRASE, HFR_TOKEN_BALANCE")

def cmd_init():
    ensure_repo_initialized()
    try:
        subprocess.check_output(["git", "rev-parse", "HEAD"])
    except Exception:
        (BASE / "README.md").write_text("# HoboFrancs Proof Folder\n\n**First created. First recorded.**\n")
        run_git(["add", "README.md"])
        run_git(["commit", "-m", f"Hobo init — {PRINCIPLE}"])
    print("✅ Hobo initialized.")

def cmd_stamp(file_path: str):
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        print("File not found:", file_path)
        sys.exit(1)
    verify_url = os.getenv("HOBO_VERIFY_URL", "https://YOUR_GH_PAGES/verify/")
    tier = "HFR" if has_hfr() else "HOBO"
    cert = build_cert(path, sha256(path), tier, None, verify_url)
    out = write_cert(path, cert)
    print("✅ HOBO STAMP created:", out)

def cmd_commit(file_path: str):
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        print("File not found:", file_path)
        sys.exit(1)
    ensure_repo_initialized()
    run_git(["add", str(path)])
    verify_url = os.getenv("HOBO_VERIFY_URL", "https://YOUR_GH_PAGES/verify/")
    tier = "HFR" if has_hfr() else "HOBO"
    msg = f"Hobo commit: {path.name}" + (" [HFR]" if tier == "HFR" else "")
    run_git(["commit", "-m", msg])
    ch = git_commit_hash()
    cert = build_cert(path, sha256(path), tier, ch, verify_url)
    out = write_cert(path, cert)
    print("✅ HOBO_ENTRY created:", out)
    print("🔗 Git commit:", ch)

def cmd_verify(file_path: str):
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        print("File not found:", file_path)
        sys.exit(1)
    cert_path = CERTS / f"{path.stem}.hobo.json"
    if not cert_path.exists():
        print("No certificate found:", cert_path)
        sys.exit(2)
    data = json.loads(cert_path.read_text())
    current_hash = sha256(path)
    match = (current_hash == data.get("file_hash"))
    print("File:", path.name)
    print("Stored hash:", data.get("file_hash"))
    print("Current hash:", current_hash)
    print("Match:", match)

def decrypt_sealed_cert_bytes(sealed_bytes: bytes, passphrase: str) -> bytes:
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.fernet import Fernet
    except Exception:
        print("Sealed operations require: pip install cryptography")
        sys.exit(5)

    salt = b"hobofrancs_seal_v1"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
    f = Fernet(key)
    return f.decrypt(sealed_bytes)

def seal_cert_file(cert_path: Path, passphrase: str) -> Path:
    try:
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        from cryptography.fernet import Fernet
    except Exception:
        print("Sealing requires: pip install cryptography")
        sys.exit(5)

    salt = b"hobofrancs_seal_v1"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
    f = Fernet(key)

    ciphertext = f.encrypt(cert_path.read_bytes())
    sealed_path = cert_path.with_suffix(cert_path.suffix + ".sealed")
    sealed_path.write_bytes(ciphertext)
    cert_path.unlink(missing_ok=True)
    return sealed_path

def cmd_unseal(sealed_file: str, passphrase: str):
    sp = Path(sealed_file)
    if not sp.exists():
        print("Sealed file not found:", sealed_file)
        sys.exit(1)
    plaintext = decrypt_sealed_cert_bytes(sp.read_bytes(), passphrase)
    out = sp.with_suffix("")
    out.write_bytes(plaintext)
    print("✅ Unsealed certificate:", out)

def cmd_verify_sealed(sealed_cert_path: str, file_path: str, passphrase: str):
    sp = Path(sealed_cert_path)
    fp = Path(file_path)
    if not sp.exists() or not sp.is_file():
        print("Sealed certificate not found:", sealed_cert_path)
        sys.exit(1)
    if not fp.exists() or not fp.is_file():
        print("File not found:", file_path)
        sys.exit(1)

    plaintext = decrypt_sealed_cert_bytes(sp.read_bytes(), passphrase)
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except Exception:
        print("Decrypted content is not valid JSON. Wrong passphrase or corrupted file.")
        sys.exit(6)

    stored_hash = data.get("file_hash")
    if not stored_hash:
        print("Invalid certificate: missing file_hash.")
        sys.exit(6)

    current_hash = sha256(fp)
    match = (current_hash == stored_hash)

    print("Sealed cert:", sp.name)
    print("File:", fp.name)
    print("Stored hash:", stored_hash)
    print("Current hash:", current_hash)
    print("Match:", match)

def github_publish_issue(owner: str, repo: str, token: str, title: str, body_json: str):
    api = os.getenv("GITHUB_API_URL", "https://api.github.com")
    url = f"{api}/repos/{owner}/{repo}/issues"
    payload = {"title": title, "body": body_json, "labels": ["hobo-stamp"]}
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"token {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "hobo-cli")
    try:
        with urllib.request.urlopen(req) as resp:
            out = json.loads(resp.read().decode("utf-8"))
            return out.get("html_url")
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="ignore")
        print("Publish failed:", e.code)
        print(msg[:800])
        sys.exit(4)

def cmd_publish_with_flags(file_path: str, flags: dict):
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        print("File not found:", file_path)
        sys.exit(1)

    repo_arg = flags.get("repo")
    owner = flags.get("owner") or os.getenv("GITHUB_OWNER")
    repo = flags.get("project") or os.getenv("GITHUB_REPO")
    if repo_arg and "/" in repo_arg:
        owner, repo = repo_arg.split("/", 1)

    token = flags.get("token") or os.getenv("GITHUB_TOKEN")
    verify_url = flags.get("verify-url") or os.getenv("HOBO_VERIFY_URL", "https://YOUR_GH_PAGES/verify/")
    title = flags.get("title") or f"Stamp: {path.name}"
    dry_run = flags.get("dry-run", False)
    do_commit = flags.get("commit", False)
    is_private = flags.get("private", False)
    want_sealed = flags.get("sealed", False)
    passphrase = flags.get("passphrase") or os.getenv("HOBO_PRIVATE_PASSPHRASE")
    force_tier = flags.get("tier")
    _ = flags.get("auto", False)

    tier = "HFR" if has_hfr() else "HOBO"
    if force_tier:
        tier = force_tier.upper()
        if tier not in ["HOBO","HFR"]:
            print("Invalid --tier. Use HOBO or HFR.")
            sys.exit(2)

    git_commit = None
    if do_commit:
        ensure_repo_initialized()
        run_git(["add", str(path)])
        msg = f"Hobo commit: {path.name}" + (" [HFR]" if tier == "HFR" else "")
        run_git(["commit", "-m", msg])
        git_commit = git_commit_hash()

    cert = build_cert(path, sha256(path), tier, git_commit, verify_url)
    cert_path = write_cert(path, cert)

    if dry_run:
        print(cert_path.read_text())
        print("\n(dry-run) Not published.")
        return

    if is_private:
        if want_sealed:
            if not passphrase:
                print("Missing passphrase for --sealed. Provide --passphrase or set HOBO_PRIVATE_PASSPHRASE.")
                sys.exit(2)
            sealed_path = seal_cert_file(cert_path, passphrase)
            print("🔒 Private sealed stamp:", sealed_path)
        else:
            print("🔒 Private local-only stamp (not published):", cert_path)
        if git_commit:
            print("🔗 Git commit:", git_commit)
        return

    if not token or not owner or not repo:
        print("Missing publish config. Provide either:")
        print("  --repo OWNER/REPO --token TOKEN")
        print("or set env vars: GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN")
        print("\nLocal stamp created:", cert_path)
        sys.exit(3)

    issue_url = github_publish_issue(owner, repo, token, title, cert_path.read_text())
    print("✅ Local stamp:", cert_path)
    print("🌍 Published issue:", issue_url)
    if git_commit:
        print("🔗 Git commit:", git_commit)

def main():
    if len(sys.argv) < 2:
        print_help(); sys.exit(0)
    if len(sys.argv) == 2 and sys.argv[1] in ("-h","--help","help"):
        print_help(); sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "init":
        cmd_init()
    elif cmd == "stamp" and len(sys.argv) == 3:
        cmd_stamp(sys.argv[2])
    elif cmd == "commit" and len(sys.argv) == 3:
        cmd_commit(sys.argv[2])
    elif cmd == "verify":
        pos, flags = parse_flags(sys.argv[2:])
        if flags.get("sealed"):
            sealed_path = flags.get("sealed")
            file_path = flags.get("file")
            pp = flags.get("passphrase") or os.getenv("HOBO_PRIVATE_PASSPHRASE")
            if not sealed_path or not file_path:
                print("Usage: python -m hobo verify --sealed <cert.sealed> --file <file> --passphrase <pass>")
                sys.exit(2)
            if not pp:
                print("Missing passphrase. Provide --passphrase or set HOBO_PRIVATE_PASSPHRASE.")
                sys.exit(2)
            cmd_verify_sealed(sealed_path, file_path, pp)
        else:
            if len(pos) != 1:
                print("Usage: python -m hobo verify <file>")
                sys.exit(2)
            cmd_verify(pos[0])
    elif cmd == "publish":
        pos, flags = parse_flags(sys.argv[2:])
        if len(pos) != 1:
            print("Usage: python -m hobo publish <file> [flags]. Try --help")
            sys.exit(2)
        cmd_publish_with_flags(pos[0], flags)
    elif cmd == "unseal":
        pos, flags = parse_flags(sys.argv[2:])
        if len(pos) != 1:
            print("Usage: python -m hobo unseal <cert.sealed> --passphrase <pass>")
            sys.exit(2)
        pp = flags.get("passphrase") or os.getenv("HOBO_PRIVATE_PASSPHRASE")
        if not pp:
            print("Missing passphrase. Provide --passphrase or set HOBO_PRIVATE_PASSPHRASE.")
            sys.exit(2)
        cmd_unseal(pos[0], pp)
    else:
        print("Unknown command. Try --help")
        sys.exit(1)

if __name__ == "__main__":
    main()
