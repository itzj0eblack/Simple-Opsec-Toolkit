import os
import socket
import random
import platform
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

def hr():
    print("-" * 60)

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def prompt(msg: str) -> str:
    return input(msg).strip()

def confirm(msg: str) -> bool:
    ans = input(f"{msg} [y/N]: ").strip().lower()
    return ans in ("y", "yes")

def is_file(path: str) -> bool:
    return Path(path).is_file()

def safe_out_path(in_path: Path, prefix: str = "clean_") -> Path:
    return in_path.with_name(prefix + in_path.name)

def try_import(name: str):
    try:
        return __import__(name)
    except Exception:
        return None

PIL = try_import("PIL")
piexif = try_import("piexif")
pypdf = try_import("pypdf")
docx_mod = try_import("docx")
requests = try_import("requests")

IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp", ".tif", ".tiff"}
PDF_EXTS = {".pdf"}
DOCX_EXTS = {".docx"}

def clean_image_metadata(path: Path) -> Tuple[bool, str, Optional[Path]]:
    if not PIL:
        return False, "Pillow is not installed ... Install: pip install pillow", None

    try:
        from PIL import Image

        out_path = safe_out_path(path, "clean_")
        img = Image.open(path)

        if img.mode in ("P", "RGBA") and path.suffix.lower() in (".jpg", ".jpeg"):
            img = img.convert("RGB")

        data = list(img.getdata())
        clean = Image.new(img.mode, img.size)
        clean.putdata(data)

        save_kwargs = {}
        if path.suffix.lower() in (".jpg", ".jpeg"):
            save_kwargs["quality"] = 95
            save_kwargs["optimize"] = True

        clean.save(out_path, **save_kwargs)

        if piexif and out_path.suffix.lower() in (".jpg", ".jpeg"):
            try:
                piexif.remove(str(out_path))
            except Exception:
                pass

        return True, "Done , Image metadata cleaned .", out_path
    except Exception as e:
        return False, f"cleaning image Failed: {e}", None

def clean_pdf_metadata(path: Path) -> Tuple[bool, str, Optional[Path]]:
    if not pypdf:
        return False, "pypdf is not installed .... Install: pip install pypdf", None

    try:
        from pypdf import PdfReader, PdfWriter

        reader = PdfReader(str(path))
        writer = PdfWriter()

        for page in reader.pages:
            writer.add_page(page)

        writer.add_metadata({})

        out_path = safe_out_path(path, "clean_")
        with open(out_path, "wb") as f:
            writer.write(f)

        return True, "Done, PDF metadata cleaned.", out_path
    except Exception as e:
        return False, f"cleaning PDF Failed: {e}", None

def clean_docx_metadata(path: Path) -> Tuple[bool, str, Optional[Path]]:
    if not docx_mod:
        return False, "python-docx is not installed ... Install: pip install python-docx", None

    try:
        import docx

        doc = docx.Document(str(path))
        props = doc.core_properties

        props.author = ""
        props.last_modified_by = ""
        props.title = ""
        props.subject = ""
        props.keywords = ""
        props.comments = ""
        props.category = ""
        props.content_status = ""
        props.identifier = ""
        props.language = ""
        props.version = ""

        out_path = safe_out_path(path, "clean_")
        doc.save(str(out_path))

        return True, "DOCX core properties cleaned", out_path
    except Exception as e:
        return False, f" cleaning DOCX Failed: {e}", None

def metadata_cleaner_menu():
    hr()
    p = prompt("Enter path to the file (image/pdf/docx): ")
    if not is_file(p):
        print("File not found , recheck again please")
        return

    path = Path(p)
    ext = path.suffix.lower()

    if ext in IMAGE_EXTS:
        ok, msg, outp = clean_image_metadata(path)
    elif ext in PDF_EXTS:
        ok, msg, outp = clean_pdf_metadata(path)
    elif ext in DOCX_EXTS:
        ok, msg, outp = clean_docx_metadata(path)
    else:
        print(f"Unsupported file extension: {ext}")
        print("Supported: extensions are (jpg/png/webp/tiff), pdf, docx")
        return

    print(msg)
    if ok and outp:
        print(f"Output: {outp}")

def shred_file(path: Path, passes: int = 3) -> Tuple[bool, str]:
    try:
        size = path.stat().st_size
        if size == 0:
            path.unlink()
            return True, "File was empty; deleted"

        try:
            os.chmod(path, 0o600)
        except Exception:
            pass

        with open(path, "r+b", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())

        rnd_name = path.with_name("." + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(12)))
        try:
            path.rename(rnd_name)
            rnd_name.unlink()
        except Exception:
            path.unlink()

        return True, f"Shredded done with {passes} pass(es) and deleted."
    except Exception as e:
        return False, f"Shred failed {e}"

def shredder_menu():
    hr()
    p = prompt("Enter path to file to shred: ")
    if not is_file(p):
        print("Are u sure? File not found.")
        return

    passes_str = prompt("Overwrite passes (default 3): ")
    passes = 3
    if passes_str:
        try:
            passes = max(1, int(passes_str))
        except Exception:
            print("Invalid number. Using default 3.")
            passes = 3

    print("INFO: In Some SSDs and some filesystems, shredding cannot be guaranteed sadly")
    if not confirm("Continue?"):
        return

    ok, msg = shred_file(Path(p), passes=passes)
    print(msg if ok else f"ERROR: {msg}")

def get_system_resolvers() -> List[str]:
    resolvers: List[str] = []

    sysname = platform.system().lower()
    if sysname in ("linux", "darwin"):
        resolv = Path("/etc/resolv.conf")
        if resolv.exists():
            for line in resolv.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        resolvers.append(parts[1])

    elif sysname == "windows":
        try:
            out = subprocess.check_output(["ipconfig", "/all"], text=True, errors="ignore")
            for line in out.splitlines():
                if "DNS Servers" in line:
                    ip = line.split(":")[-1].strip()
                    if ip:
                        resolvers.append(ip)
                elif resolvers and line.strip() and line.startswith(" " * 10):
                    ip = line.strip()
                    if ip and any(c.isdigit() for c in ip):
                        resolvers.append(ip)
        except Exception:
            pass

    return list(dict.fromkeys(resolvers))

def resolve_test(domains: List[str]) -> List[Tuple[str, Optional[str], Optional[str]]]:
    results: List[Tuple[str, Optional[str], Optional[str]]] = []
    for d in domains:
        try:
            ip = socket.gethostbyname(d)
            results.append((d, ip, None))
        except Exception as e:
            results.append((d, None, str(e)))
    return results

def dns_diagnostics_menu():
    hr()
    print("DNS diagnostics (Its not a DNS leak test, Don't Worry)")

    resolvers = get_system_resolvers()
    if resolvers:
        print("System-configured DNS resolvers:")
        for r in resolvers:
            print(f"  - {r}")
    else:
        print("I Could not reliably parse system resolvers")

    print()
    domains = ["example.com", "cloudflare.com", "google.com"]
    print("Testing resolution via system resolver path:")
    for d, ip, err in resolve_test(domains):
        if err:
            print(f"  {d}: ERROR {err}")
        else:
            print(f"  {d}: {ip}")

    print("\nIf you’re using a VPN, compare the resolver IPs above with your expected VPN DNS servers.")
    print("I cannot confirm 'no DNS leak' from this output alone.")

SITE_TEMPLATES = [
    ("GitHub", "https://github.com/{}"),
    ("GitLab", "https://gitlab.com/{}"),
    ("Reddit", "https://www.reddit.com/user/{}"),
    ("Twitter/X", "https://x.com/{}"),
    ("Instagram", "https://www.instagram.com/{}/"),
    ("Medium", "https://medium.com/@{}"),
    ("Dev.to", "https://dev.to/{}"),
]

def http_exists(url: str, timeout: int = 7) -> Tuple[Optional[bool], str]:
    try:
        if requests:
            r = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "opsec-toolkit/1.0"},
            )

            if r.status_code == 200:
                return True, f"200 OK ({r.url})"
            if r.status_code == 404:
                return False, "404 Not Found"
            if r.status_code in (401, 403, 429):
                return None, f"{r.status_code} Blocked/Rate-limited"
            return None, f"{r.status_code} Unknown"

        import urllib.request

        req = urllib.request.Request(url, headers={"User-Agent": "opsec-toolkit/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = getattr(resp, "status", 200)
            if code == 200:
                return True, "200 OK"
            return None, f"{code} Unknown"

    except Exception as e:
        return None, f"Error/Blocked: {e}"

def footprint_menu():
    hr()
    username = prompt("Enter username to check: ")
    if not username:
        print("No username provided.")
        return

    print(f"Checking footprint for: {username}")
    hr()

    for site, tmpl in SITE_TEMPLATES:
        url = tmpl.format(username)
        exists, note = http_exists(url)

        if exists is True:
            status = "FOUND"
        elif exists is False:
            status = "NOT FOUND"
        else:
            status = "UNKNOWN"

        print(f"{site:12} {status:10} {url}  |  {note}")

    print("\nNote: UNKNOWN often means the site blocked automated checks. This is not conclusive")

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 587, 631, 8080, 8443, 3306, 5432, 6379, 27017]

def scan_port(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False

def local_scan_menu():
    hr()
    host = prompt("Host to scan (default 127.0.0.1): ") or "127.0.0.1"
    mode = prompt("Scan mode: 1) common ports  2) custom range  (default 1): ") or "1"

    ports: List[int] = []
    if mode.strip() == "2":
        start = prompt("Start port (e.g., 1): ")
        end = prompt("End port (e.g., 1024): ")
        try:
            a, b = int(start), int(end)
            if a < 1 or b > 65535 or a > b:
                raise ValueError
            ports = list(range(a, b + 1))
        except Exception:
            print("Invalid range. Using common ports.")
            ports = COMMON_PORTS
    else:
        ports = COMMON_PORTS

    timeout_s = prompt("Timeout per port in seconds (default 0.4): ") or "0.4"
    try:
        timeout = float(timeout_s)
        if timeout <= 0:
            raise ValueError
    except Exception:
        timeout = 0.4

    print(f"\nScanning {host} on {len(ports)} port(s)...")
    open_ports: List[int] = []

    for p in ports:
        if scan_port(host, p, timeout=timeout):
            open_ports.append(p)

    hr()
    if open_ports:
        print("Open ports:")
        print(", ".join(map(str, open_ports)))
    else:
        print("No open ports found (or filtered).")

MENU = {
    "1": ("Metadata cleaner (image/pdf/docx)", metadata_cleaner_menu),
    "2": ("Shred file (it overwrite + delete)", shredder_menu),
    "3": ("DNS diagnostics (not definitive leak test)", dns_diagnostics_menu),
    "4": ("Username checker in other platforms", footprint_menu),
    "5": ("Simple Local port scan", local_scan_menu),
    "0": ("Exit", None),
}

def show_deps():
    print("dependencies status:")
    print(f"  pillow:      {'OK' if PIL else 'missing'}")
    print(f"  piexif:      {'OK' if piexif else 'missing'}")
    print(f"  pypdf:       {'OK' if pypdf else 'missing'}")
    print(f"  python-docx: {'OK' if docx_mod else 'missing'}")
    print(f"  requests:    {'OK' if requests else 'missing'}")
    print("Install missing ones with: pip install pillow piexif pypdf python-docx requests")

def main():
    clear_screen()
    print("OPSEC Toolkit")
    print("Made by Sami Salhi")
    show_deps()

    while True:
        hr()
        for k in sorted(MENU.keys(), key=lambda x: int(x) if x.isdigit() else 999):
            print(f"{k}. {MENU[k][0]}")
        hr()

        choice = prompt("Please Choose an option: ")
        if choice == "0":
            print("Bye <3.")
            break

        if choice in MENU:
            fn = MENU[choice][1]
            if fn:
                fn()
                input("\nPress Enter to return to menu...")
                clear_screen()
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
