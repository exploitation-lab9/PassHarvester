# PassHarvester

**Advanced password wordlist builder for penetration testing and security research.**

PassHarvester recursively scans directories of any size — from small config folders to 100GB+ breach dumps — and extracts passwords into a clean, deduplicated wordlist. Output is directly compatible with **hashcat**, **John the Ripper**, **aircrack-ng**, and any tool that accepts a wordlist file.

Built for real-world pentesting workflows: constant memory usage, crash-safe checkpointing, live progress tracking, and instant Ctrl+C saves — even mid-way through an 100GB+ file.

---

## Features

**Scanning**
- 5 scan modes: general, credentials, combo, hash, wifi — plus custom regex
- Multilingual password detection across 30+ languages (English, Chinese, Russian, Spanish, Japanese, Arabic, Korean, German, French, and 20+ more)
- Streams files line-by-line with constant ~50-200MB memory regardless of file size
- SQLite-backed storage handles hundreds of millions of unique passwords
- Multithreaded scanning with thread-safe deduplication

**Output & Export**
- 4 output formats: plain, frequency-sorted, potfile (hashcat), john
- Hashcat rules file generation (34 mutation rules)
- Hashcat mask file generation (top 100 password structure patterns)
- Hash type auto-identification with hashcat `-m` mode numbers
- Username/email extraction from combo lists
- JSON and CSV export with full metadata (frequency, entropy, source tracking)

**Filtering & Analysis**
- Shannon entropy filtering to remove low-quality matches
- Exclusion wordlists (subtract rockyou.txt, etc.)
- Case-insensitive deduplication
- Password policy validator (min/max length, required character classes)
- File extension, directory depth, and date-based filtering
- Password reuse report (cross-file analysis)
- Password age estimation (year pattern detection)

**Reliability**
- Live progress bar with intra-file byte tracking, MB/s throughput, ETA, and wordlist size
- Background auto-save every 30-60 seconds — even mid-file
- Instant Ctrl+C save (passwords written to disk within seconds)
- Second Ctrl+C force-quits immediately
- Resume from checkpoint after interruption or crash
- Incremental scanning (only process files changed since last run)

**Utilities**
- Wordlist comparison (overlap analysis between two files)
- Wordlist merging with deduplication and filtering
- Config file support for saved scan presets
- Colored terminal output with `--no-color` option

---

## Requirements

- **Python 3.9+**
- **No external dependencies** — uses only Python standard library modules

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/PassHarvester.git
cd PassHarvester
chmod +x PassHarvester.py
```

No pip install needed. Just run it.

---

## Quick Start

```bash
# Scan a breach dump for passwords (combo format: user:password)
python3 PassHarvester.py /path/to/breach -m combo -o ~/wordlist.txt

# Scan config files for credentials
python3 PassHarvester.py /var/www -m credentials --extensions ".env,.conf,.yml" -o ~/creds.txt

# Extract Wi-Fi passwords from router backups
python3 PassHarvester.py ~/router_backups -m wifi -o ~/wifi.txt

# Full cracking toolkit in one command
python3 PassHarvester.py /breach -m combo -t 8 -f frequency \
    --rules --masks --stats --extract-users -o ~/crack/wordlist.txt

# Scan everything with all modes
python3 PassHarvester.py /data -m all -t 4 --stats -o ~/wordlist.txt
```

---

## Scan Modes

| Mode | Description | Best For |
|------|-------------|----------|
| `general` | Any 6+ char Unicode word string | Raw dumps, mixed data |
| `credentials` | Values after password labels in 30+ languages | Config files, .env, YAML, logs |
| `combo` | Password from `email:password` format | Breach dumps, combo lists |
| `hash` | MD5, SHA1, SHA256, bcrypt, NTLM hashes | Database dumps, hash files |
| `wifi` | Wi-Fi password fields in 20+ languages | Router configs, wpa_supplicant |
| `all` | All modes combined | Maximum coverage |

---

## Usage Examples

### Pentest Workflow — Breach Dump to Hashcat

```bash
python3 PassHarvester.py /mnt/breach -m combo -t 4 -f frequency \
    --rules --masks --stats --extract-users --hash-id \
    -o ~/crack/wordlist.txt
```

This generates:
```
~/crack/wordlist.txt           Frequency-sorted wordlist
~/crack/wordlist.rule          Hashcat rules (34 mutations)
~/crack/wordlist.hcmask        Hashcat masks (top 100 patterns)
~/crack/wordlist_users.txt     Extracted usernames/emails
~/crack/wordlist_stats.txt     Password statistics report
```

Then crack with hashcat:
```bash
hashcat -m 0 hashes.txt ~/crack/wordlist.txt -r ~/crack/wordlist.rule
```

### Large-Scale Scanning (100GB+)

For scanning large directories on external drives:

```bash
# Read from external HDD, write to internal SSD
# ionice/nice prevent system freezes on slow drives
ionice -c 3 nice -n 19 python3 PassHarvester.py /mnt/external_drive \
    -m combo -t 1 -o ~/Desktop/wordlist.txt --resume
```

**Important for external HDDs:**
- Always write output to a **different drive** than the one being scanned
- Use `-t 1` or `-t 2` for spinning drives (more threads cause seek thrashing)
- Use `ionice -c 3 nice -n 19` to prevent system freezes
- The `--resume` flag enables checkpoint recovery if interrupted

### Security Audit with Source Tracking

```bash
python3 PassHarvester.py /data -m all \
    --track-sources --reuse-report --age-report \
    --export-json --export-csv \
    -o ~/audit/wordlist.txt
```

### Filter for Target Password Policy

```bash
python3 PassHarvester.py /data -m combo \
    --policy "min_length:8,require_upper,require_digit,require_special" \
    --min-entropy 3.0 --dedup-case \
    -o ~/filtered.txt
```

### Compare and Merge Wordlists

```bash
# Compare overlap between two wordlists
python3 PassHarvester.py --compare wordlist1.txt wordlist2.txt

# Merge multiple wordlists with deduplication
python3 PassHarvester.py --merge list1.txt list2.txt list3.txt -o merged.txt
```

---

## Progress Bar

PassHarvester shows live progress with real-time updates — even during a single massive file:

```
|████████░░░░░░░░░░░░░░░░░░░░░░░░░░░| 12.3 GB/88.43 GB (14%)  1/2 files  4.1 MB/s  Matches: 1,847,293  WL: 847.2 MB  [6m22s < 39m15s]
```

- **Progress bar** — byte-level, updates every 1MB even during huge files
- **File count** — files completed / total
- **Throughput** — MB/s read speed
- **Matches** — passwords found so far (updates in real-time)
- **WL** — current wordlist database size on disk
- **ETA** — estimated time remaining

---

## Interrupt Handling

| Action | Behavior |
|--------|----------|
| **Ctrl+C (first)** | Immediately saves all passwords found so far to the wordlist file and checkpoint. Prints confirmation. |
| **Ctrl+C (second)** | Force quits instantly with `os._exit(1)`. |
| **`--resume`** | Resumes from the last checkpoint. Use the same output path and start directory. |

Background auto-save writes the wordlist every 30-60 seconds automatically, so even a hard crash or power failure preserves most progress.

---

## All Command-Line Options

```
Usage: PassHarvester.py [start_directory] [options]

Scan Mode:
  -m, --mode              general, credentials, combo, hash, wifi, all
  -p, --pattern           Custom regex pattern (overrides --mode)
  --keywords              Custom keyword file for credentials/wifi mode
  --list-modes            Show mode descriptions

Output:
  -o, --output            Output file path (default: ./wordlist.txt)
  -f, --format            plain, frequency, potfile, john
  --rules                 Generate hashcat .rule file
  --masks                 Generate hashcat .hcmask file
  --stats                 Generate statistics report
  --export-json           Export as JSON with metadata
  --export-csv            Export as CSV with metadata

Filtering:
  --min-entropy           Minimum Shannon entropy (0 = disabled)
  --dedup-case            Case-insensitive deduplication
  --exclude               Wordlist to subtract from results
  --policy                Password policy filter
  --extensions            File extensions to scan (e.g. .txt,.conf,.env)
  --max-depth             Max directory recursion depth
  --newer-than            Only files modified after date (YYYY-MM-DD)

Performance:
  -t, --threads           Parallel threads (default: 1)
  --resume                Resume from checkpoint
  --incremental           Only scan files changed since last run

Analysis:
  --track-sources         Track source file and line for each password
  --extract-users         Extract usernames to separate file
  --hash-id               Identify hash types with hashcat mode numbers
  --reuse-report          Passwords found across multiple files
  --age-report            Year pattern timeline

Utilities:
  --compare FILE FILE     Compare two wordlists
  --merge FILE [FILE ...] Merge wordlists with dedup
  --config                Load settings from INI file
  --generate-config       Create sample config file
  --no-color              Disable colored output
  -v, --verbose           Per-file progress (disables bar)
```

---

## Multilingual Support

Credentials and Wi-Fi modes detect password labels in 30+ languages:

| Language | Example Labels |
|----------|---------------|
| English | password, passwd, secret, token, api_key |
| Chinese | 密码, 口令, 秘密 |
| Spanish | contraseña, clave, secreto |
| Russian | пароль, секрет, ключ |
| Japanese | パスワード, 暗証番号 |
| Korean | 비밀번호, 암호, 비번 |
| German | passwort, kennwort, geheimnis |
| French | mot_de_passe, mdp |
| Arabic | كلمة_السر, كلمة_المرور |
| Hindi | पासवर्ड, गुप्त |
| + 20 more | Turkish, Italian, Vietnamese, Thai, Polish, Dutch, Czech, Greek, Romanian, Swedish, Finnish, Danish, Norwegian, Hungarian, Ukrainian, Indonesian, Persian, Hebrew, Bengali, Urdu, Swahili |

---

## Architecture

```
1. DISCOVER  → Walk directory tree with filters (extensions, depth, date)
2. FILTER    → Skip binary files (extension + null-byte heuristic)
3. STREAM    → Read line-by-line (1MB buffer, constant memory)
4. MATCH     → Apply regex patterns per line
5. FLUSH     → Write matches to SQLite every 1MB (crash-safe)
6. AUTOSAVE  → Background thread snapshots wordlist every 30-60 seconds
7. POST-PROC → Apply exclusions, case dedup, policy filter
8. OUTPUT    → Write final wordlist + optional exports
```

**Encoding handling:** Each file is tried with UTF-8 → UTF-8-BOM → CP1252 → Latin-1, with strict error detection so mismatches are caught properly.

---

## Legal & Ethical Notice

**This tool is intended exclusively for authorized security testing, penetration testing, and forensic analysis.**

- Always obtain **written authorization** before scanning directories, systems, or networks
- Only use on systems and data you **own** or have **explicit permission** to test
- Comply with all applicable **local, state, national, and international laws**
- Unauthorized access to computer systems and data is **illegal** in most jurisdictions and can result in criminal prosecution
- The authors assume **no liability** for misuse of this tool
- By using this software, you agree to use it **responsibly and ethically**

This tool does not perform any network attacks, credential stuffing, or unauthorized access. It is a local file scanner that extracts text patterns from files you already have access to.

---

## License

GPL v3

---

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.

---

*PassHarvester — Built for scale, precision, and multilingual coverage.*
