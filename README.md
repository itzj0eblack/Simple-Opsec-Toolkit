#  OPSEC Toolkit

A lightweight command-line toolkit for everyday operational security tasks.

I built this project to automate small but important privacy habits during pentesting, research, and daily use — like removing metadata, securely deleting sensitive files, checking DNS configuration, scanning local exposure, and doing quick username footprint checks.

Instead of juggling multiple tools, everything is bundled into one simple Python script.

---

##  Features

- Remove metadata from images, PDFs and DOCX files
- file shredder (it overwrite + delete)
- DNS diagnostics (check which resolvers your system uses)
- Username checker across common platforms
- Local TCP port scanner
- It Works offline (except username checks)
- Lightweight and easy to run

## ⚙️ Installation

### 1) Clone the repository

```bash
git clone https://github.com/itzj0eblack/Simple-Opsec-Toolkit.git
cd opsec-toolkit
```

### 2) Install dependencies 

```bash
pip install -r requirements.txt
```

# Limitations

Shredding is not guaranteed on SSDs or copy-on-write filesystems
DNS check is not a full leak test (no packet capture)
Username checks may be blocked or rate limited
Port scanner is basic TCP only
