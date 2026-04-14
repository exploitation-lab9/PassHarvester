# PassHarvester v4.0 — User Guide & Reference

## Table of Contents

1.  [Overview](#overview)
2.  [System Requirements](#system-requirements)
3.  [Installation](#installation)
4.  [Quick Start](#quick-start)
5.  [Scan Modes](#scan-modes)
6.  [Command Line Reference](#command-line-reference)
7.  [Output Formats](#output-formats)
8.  [Filtering Options](#filtering-options)
9.  [Performance & Threading](#performance--threading)
10. [Resume & Checkpointing](#resume--checkpointing)
11. [Incremental Scanning](#incremental-scanning)
12. [Config Files](#config-files)
13. [Statistics Report](#statistics-report)
14. [Hashcat Rules File](#hashcat-rules-file)
15. [Hashcat Mask File](#hashcat-mask-file)
16. [Hash Type Identification](#hash-type-identification)
17. [Username Extraction](#username-extraction)
18. [Password Reuse Report](#password-reuse-report)
19. [Password Age Estimation](#password-age-estimation)
20. [JSON & CSV Export](#json--csv-export)
21. [Wordlist Comparison](#wordlist-comparison)
22. [Wordlist Merging](#wordlist-merging)
23. [Password Policy Filtering](#password-policy-filtering)
24. [Custom Keywords](#custom-keywords)
25. [File Type & Date Filtering](#file-type--date-filtering)
26. [Color Output](#color-output)
27. [Multilingual Support](#multilingual-support)
28. [Using with Cracking Tools](#using-with-cracking-tools)
29. [Large-Scale Scanning (100GB+)](#large-scale-scanning-100gb)
30. [Progress Bar & Live Monitoring](#progress-bar--live-monitoring)
31. [Interrupt Handling & Auto-Save](#interrupt-handling--auto-save)
32. [Architecture & How It Works](#architecture--how-it-works)
33. [Troubleshooting](#troubleshooting)
34. [Examples & Recipes](#examples--recipes)
35. [All Generated Files Reference](#all-generated-files-reference)

---

## Overview

PassHarvester is a command-line tool that recursively scans directories for
password-like strings and builds a deduplicated wordlist file. It is designed for
penetration testers, security researchers, and forensic analysts who need to
extract passwords from data breach dumps, config files, log files, combo lists,
and other text-based sources.

The output is a plain-text file with one password per line, directly compatible with:

- **hashcat** — GPU-accelerated password cracker
- **John the Ripper** — CPU-based password cracker
- **aircrack-ng** — Wi-Fi password cracker
- Any other tool that accepts a wordlist/dictionary file

### Key Features

**Core Scanning:**
- Streams files line-by-line (constant memory, handles multi-GB files)
- SQLite-backed password storage (handles hundreds of millions of entries)
- Multilingual detection across 30+ languages and all Unicode scripts
- 5 preset scan modes + custom regex support
- Multithreaded scanning for faster processing

**Output & Export:**
- 4 output formats (plain, frequency-sorted, potfile, john)
- JSON export with full metadata (frequency, entropy, source files)
- CSV export for spreadsheet analysis
- Hashcat rules file generation (34 mutation rules)
- Hashcat mask file generation (password pattern analysis)
- Hash type auto-identification with hashcat mode numbers
- Username extraction from combo lists

**Filtering & Analysis:**
- Entropy-based filtering to remove low-quality matches
- Exclusion wordlists (subtract rockyou.txt, etc.)
- Case-insensitive deduplication
- Password policy validator (min length, required char classes)
- File extension targeting
- Directory depth limiting
- Date-based file filtering
- Password reuse report (cross-file analysis)
- Password age estimation (year pattern detection)

**Reliability:**
- Auto-checkpointing with resume on interrupt
- Incremental scanning (only process changed files)
- Partial wordlist written on every checkpoint and interrupt
- Config file support for saved settings

**Utilities:**
- Wordlist comparison (overlap analysis)
- Wordlist merging with deduplication
- Colored terminal output with --no-color option

---

## System Requirements

### Python Version

**Python 3.9 or higher is required.**

The script uses `concurrent.futures.ThreadPoolExecutor.shutdown(cancel_futures=True)`
which was introduced in Python 3.9. It also requires SQLite 3.25.0+ for window
functions, which ships with Python 3.7.2+.

To check your Python version:

    python3 --version

### Dependencies

**None.** PassHarvester uses only Python standard library modules. There is
nothing to install beyond Python itself.

Standard library modules used: os, sys, re, math, json, time, signal, sqlite3,
argparse, configparser, csv, datetime, pathlib, collections, typing,
concurrent.futures, threading.

### Operating System

Works on any OS with Python 3.9+: Linux, macOS 10.15+, Windows 10/11.
On Windows, use `python` instead of `python3`.

### Disk Space

The script creates a temporary SQLite database during scanning, roughly the same
size as the final wordlist. It is automatically deleted when the scan completes.
Budget approximately 2x the expected wordlist size for temporary disk usage.

---

## Installation

No installation is required. Download or copy `PassHarvester.py` and run it.

    # Make it executable (Linux/macOS)
    chmod +x PassHarvester.py

    # Verify it runs
    python3 PassHarvester.py -h

### Optional: Add to PATH

    # Linux/macOS
    sudo cp PassHarvester.py /usr/local/bin/passharvester
    sudo chmod +x /usr/local/bin/passharvester

    # Now run from anywhere
    passharvester /path/to/data -m combo -o ~/wordlist.txt

---

## Quick Start

### Basic scan (general mode)

    python3 PassHarvester.py /path/to/directory

### Scan a breach dump for combo-list passwords

    python3 PassHarvester.py /path/to/breach -m combo -o ~/wordlist.txt

### Fast scan with 8 threads, stats, and rules

    python3 PassHarvester.py /path/to/data -m all -t 8 --stats --rules -o ~/wordlist.txt

### Full cracking toolkit in one command

    python3 PassHarvester.py /breach -m combo -t 8 -f frequency \
        --rules --masks --stats --extract-users -o ~/crack/wordlist.txt

### View all options

    python3 PassHarvester.py -h

### View scan mode descriptions

    python3 PassHarvester.py --list-modes

---

## Scan Modes

Use `-m` or `--mode` to select a scan mode. Each mode uses a different regex
pattern optimized for a specific type of data source.

### general (default)

    python3 PassHarvester.py /data -m general

Matches any Unicode word-character string of 6 or more characters. Covers Latin,
Cyrillic, Chinese, Japanese, Korean, Arabic, Devanagari, and all other Unicode
scripts.

**Best for:** Directories known to contain passwords, raw dumps.
**Downside:** Broad and noisy — also matches variable names, function names,
English words. Use `--min-entropy` to filter.

### credentials

    python3 PassHarvester.py /data -m credentials

Captures values after password-related labels in 30+ languages.

**English:** password=, passwd:, pwd=, secret=, token=, api_key=, auth=
**Other languages:** 密码=, пароль=, contraseña=, Passwort=, mot_de_passe:,
パスワード=, 비밀번호=, şifre=, hasło=, senha=, κωδικός=, and many more.

**Best for:** Config files, .env files, application logs, YAML, XML settings.

### combo

    python3 PassHarvester.py /data -m combo

Extracts the password portion from combo-list formats:
- `email@example.com:Password123` → extracts `Password123`
- `username:password` → extracts `password`
- `user@domain.com;password` → extracts `password`

**Best for:** Data breach combo lists, credential dumps, leaked databases.

### hash

    python3 PassHarvester.py /data -m hash

Extracts hash strings: MD5 (32 hex), SHA1 (40 hex), SHA256 (64 hex),
bcrypt ($2b$...), NTLM-style (hash:hash).

**Best for:** Dumped databases, hashdump files. Pair with `--hash-id`.

### wifi

    python3 PassHarvester.py /data -m wifi

Targets Wi-Fi credential fields in 20+ languages: psk=, passphrase=,
wpa_passphrase=, wifi密码=, wlan_passwort=, пароль_wifi=, and more.

**Best for:** Router configs, wpa_supplicant files, Wi-Fi config exports.

### all

    python3 PassHarvester.py /data -m all

Runs every mode simultaneously and merges results. Most comprehensive but noisiest.

### Custom pattern

    python3 PassHarvester.py /data -p 'your_regex_here'

Overrides the mode with your own regex. Use a capturing group `()` to extract
only part of the match.

    # Extract values after "key=" labels
    python3 PassHarvester.py /data -p '(?i)key\s*[=:]\s*(\S+)'

---

## Command Line Reference

    python3 PassHarvester.py [start_directory] [options]
    python3 PassHarvester.py --compare file1.txt file2.txt
    python3 PassHarvester.py --merge file1.txt file2.txt -o merged.txt

### Positional Arguments

    start_directory          Root directory to scan recursively.

### Scan Mode Options

    -m, --mode MODE          Scan mode: general, credentials, combo, hash, wifi, all
    --list-modes             Show scan mode descriptions and exit.
    -p, --pattern REGEX      Custom regex pattern — overrides --mode.
    --keywords FILE          Custom keyword file for credentials/wifi mode.

### Output Options

    -o, --output PATH        Output file path (default: ./wordlist.txt).
    -f, --format FORMAT      Output format: plain, frequency, potfile, john.
    --rules                  Generate a hashcat .rule file.
    --masks                  Generate a hashcat .hcmask mask file.
    --stats                  Generate a password statistics report.
    --export-json            Export passwords as JSON with metadata.
    --export-csv             Export passwords as CSV with metadata.

### Filtering Options

    --min-entropy N          Minimum Shannon entropy in bits/char (default: 0).
    --dedup-case             Case-insensitive deduplication.
    --exclude PATH           Wordlist to subtract from results.
    --policy RULES           Password policy filter (see Policy Filtering section).
    --extensions EXTS        Comma-separated file extensions (e.g. .txt,.conf,.env).
    --max-depth N            Maximum directory recursion depth.
    --newer-than DATE        Only scan files modified after DATE (YYYY-MM-DD).

### Performance Options

    -t, --threads N          Number of parallel scanning threads (default: 1).
    --resume                 Resume from last checkpoint.
    --incremental            Only scan files modified since last run.

### Analysis Options

    --track-sources          Track which file each password came from.
    --extract-users          Extract usernames from combo lists to separate file.
    --hash-id                Identify hash types and show hashcat mode numbers.
    --reuse-report           Show passwords found across multiple source files.
    --age-report             Estimate password ages from year patterns.

### Utility Options

    --compare FILE FILE      Compare two wordlists (overlap analysis).
    --merge FILE [FILE ...]  Merge multiple wordlists into one.
    --config PATH            Load settings from an INI config file.
    --generate-config PATH   Generate a sample config file and exit.
    --no-color               Disable colored terminal output.
    -v, --verbose            Print per-file progress (disables progress bar).
    -h, --help               Show help message and exit.

---

## Output Formats

### plain (default)

One password per line, sorted alphabetically.

    Password123
    Secret456!
    admin1234

### frequency

Sorted by occurrence count (most common first). Useful for prioritizing
high-probability passwords during cracking. The output file contains only
the passwords — use `--stats` to see the actual frequency counts.

    Password123
    123456
    admin1234
    Summer2024!

### potfile

hashcat .potfile format: `<hash>:password`

    <hash>:Password123
    <hash>:Secret456!

### john

John the Ripper format: `user:password`

    user:Password123
    user:Secret456!

---

## Filtering Options

### Entropy Filter (--min-entropy)

Shannon entropy measures randomness in bits per character.

    Entropy  | Examples                  | Typical Content
    ---------|---------------------------|------------------
    < 2.0    | aaaaaa, 111111            | Repeated characters
    2.0-2.5  | password, localhost        | Common English words
    2.5-3.0  | hunter2, Summer2024        | Simple passwords
    3.0-3.5  | MyS3cret!, P@ssw0rd        | Mixed-class passwords
    3.5-4.0  | xK9#mF2$vL                 | Complex passwords
    > 4.0    | dKj2$fLp9!xQm             | Very high randomness

**Recommended:** `--min-entropy 2.5` removes common words; `--min-entropy 3.0`
keeps only mixed-class passwords.

### Case-Insensitive Dedup (--dedup-case)

Collapses `Password123` and `password123` into one entry, keeping the version
found most frequently.

### Exclusion Wordlist (--exclude)

Subtracts passwords already in another wordlist. Streamed line-by-line so the
exclusion file can be any size (e.g. rockyou.txt at 133MB).

    python3 PassHarvester.py /data -m combo --exclude /usr/share/wordlists/rockyou.txt

---

## Performance & Threading

### Thread Count Guidelines

    Storage Type     | Recommended    | Notes
    -----------------|----------------|------------------------------
    SSD (NVMe)       | 8-16           | I/O is fast, CPU bottleneck
    SSD (SATA)       | 4-8            | Good balance
    HDD (internal)   | 2-4            | Too many threads cause seek thrash
    Network/NAS      | 4-8            | Depends on bandwidth
    HDD (external)   | 1-2            | Slow I/O, minimize seeking
    USB drive        | 1              | Slow I/O, single thread only

    python3 PassHarvester.py /data -m combo -t 8

### Critical Rule for External HDDs

**Always write output to a different drive than the one being scanned.**

Reading and writing to the same spinning HDD causes the disk head to thrash
back and forth, which can freeze the system and corrupt the filesystem.

    # CORRECT — read from external, write to internal SSD
    python3 PassHarvester.py /mnt/external -m combo -t 1 -o ~/Desktop/wordlist.txt

    # DANGEROUS — read and write on same external drive
    python3 PassHarvester.py /mnt/external -m combo -o /mnt/external/wordlist.txt

### Preventing System Freezes on Slow Drives

Use ionice and nice to give the script lowest I/O and CPU priority:

    ionice -c 3 nice -n 19 python3 PassHarvester.py /mnt/external \
        -m combo -t 1 -o ~/Desktop/wordlist.txt

This allows your desktop, browser, and terminal to remain responsive while
the scan runs in the background.

### Pausing and Resuming Without Killing

    # Pause the scan (from a second terminal)
    kill -STOP $(pgrep -f PassHarvester)

    # Resume it later
    kill -CONT $(pgrep -f PassHarvester)

### Memory Usage

The script uses constant memory regardless of file size (line-by-line streaming
+ SQLite on disk). Typical memory usage is 50-200 MB even for terabytes of data.

---

## Resume & Checkpointing

### How It Works

Passwords are flushed to SQLite every 1MB of data read — not just at file
boundaries. A background auto-save thread writes the wordlist and checkpoint
every 30-60 seconds, even mid-file. This means progress is preserved even
during a hard crash while processing a single massive file.

### Interrupting a Scan

Press Ctrl+C once. The signal handler immediately:
1. Flushes all pending passwords to SQLite
2. Writes the wordlist file
3. Saves the checkpoint
4. Prints a confirmation with the password count

A second Ctrl+C force-quits immediately without saving.

### Resuming

    python3 PassHarvester.py /same/directory -m same_mode -o same/output.txt --resume

Use the same output path and start directory. The checkpoint is directory-matched.

### Checkpoint Files

    /output/dir/wordlist.txt                            # Your wordlist
    /output/dir/.passharvester_checkpoint.json       # Checkpoint
    /output/dir/.passharvester_temp.db               # Temp database

All cleaned up automatically when a scan completes successfully.

---

## Incremental Scanning

The `--incremental` flag tracks file modification times. On subsequent runs,
only files that have been modified since the last scan are processed.

    # First run — scans everything
    python3 PassHarvester.py /data -m credentials --incremental -o ~/wordlist.txt

    # Second run — only scans new/changed files
    python3 PassHarvester.py /data -m credentials --incremental -o ~/wordlist.txt

State is stored in `.passharvester_state.json` alongside the output file.

This is different from `--resume`: resume continues an interrupted scan of the
same directory, while incremental re-scans only changed files across separate runs.

---

## Config Files

### Generate a sample config

    python3 PassHarvester.py --generate-config my_settings.ini

### Use a config file

    python3 PassHarvester.py /data --config my_settings.ini

### Priority

Command-line flags override config file values. You can have a base config and
override specific settings per run:

    python3 PassHarvester.py /data --config settings.ini -m combo -t 8

### Available Config Options

    [scanner]
    mode = general                    # general, credentials, combo, hash, wifi, all
    output = wordlist.txt
    format = plain                    # plain, frequency, potfile, john
    min_entropy = 0                   # 0 = disabled, suggested 2.5-3.0
    threads = 4
    verbose = false
    stats = false
    rules = false
    masks = false
    dedup_case = false
    resume = false
    incremental = false
    no_color = false
    track_sources = false
    extract_users = false
    hash_id = false
    reuse_report = false
    age_report = false
    export_json = false
    export_csv = false
    # exclude = /path/to/rockyou.txt
    # extensions = .txt,.conf,.env
    # max_depth = 5
    # keywords = /path/to/keywords.txt
    # policy = min_length:8,require_upper
    # newer_than = 2024-01-01
    # pattern = custom_regex

---

## Statistics Report

    python3 PassHarvester.py /data -m combo --stats -o ~/wordlist.txt

Generates and saves a detailed analysis including:

- **Length distribution** — min, max, average, median, histogram by range
- **Character class usage** — percentage with lowercase, uppercase, digits,
  special chars, mixed case, all 4 classes
- **Entropy analysis** — min, max, average, weak/medium/strong breakdown
- **Common patterns** — ends with digits, ends with special, starts uppercase,
  contains a year
- **Top 20 most frequent** — passwords ranked by occurrence count

For datasets over 5 million entries, statistics are sampled from 100,000 random
entries to keep analysis fast. The report notes when sampling is used.

Stats are saved to `wordlist_stats.txt` alongside your wordlist.

---

## Hashcat Rules File

    python3 PassHarvester.py /data -m combo --rules -o ~/wordlist.txt

Generates a `.rule` file with 34 hashcat-compatible mutation rules:

- **Case variations:** lowercase, uppercase, capitalize, toggle
- **Common suffixes:** !, 1, 123, 2024-2026, @, #, $
- **Common prefixes:** 1, !
- **Leet-speak:** a→@, e→3, i→1, o→0, s→$, t→7
- **Transformations:** reverse, rotate, duplicate
- **Combinations:** capitalize+suffix, lowercase+append

### Usage with hashcat

    hashcat -m 0 hashes.txt ~/wordlist.txt -r ~/wordlist.rule

---

## Hashcat Mask File

    python3 PassHarvester.py /data -m combo --masks -o ~/wordlist.txt

Analyzes every password's character structure and generates a `.hcmask` file
with the top 100 most common patterns.

Each character is classified:  ?l = lowercase, ?u = uppercase, ?d = digit, ?s = special

Example: `Password1!` becomes `?u?l?l?l?l?l?l?l?d?s`

### Usage with hashcat (mask attack)

    hashcat -m 0 hashes.txt -a 3 ~/wordlist.hcmask

This runs a targeted brute-force using only the password structures actually
found in your data, which is far more efficient than generic masks.

---

## Hash Type Identification

    python3 PassHarvester.py /data -m hash --hash-id -o ~/wordlist.txt

When using hash mode, this flag auto-identifies each hash type and displays
the corresponding hashcat mode number.

**Supported hash types:**

    Hash Type        | Length/Pattern  | hashcat -m
    -----------------|----------------|------------
    MD5              | 32 hex chars   | -m 0
    NTLM             | 32 hex chars   | -m 1000
    SHA-1            | 40 hex chars   | -m 100
    SHA-256          | 64 hex chars   | -m 1400
    SHA-512          | 128 hex chars  | -m 1700
    bcrypt           | $2b$...        | -m 3200
    md5crypt         | $1$...         | -m 500
    sha256crypt      | $5$...         | -m 7400
    sha512crypt      | $6$...         | -m 1800

Output shows the count of each hash type found and the hashcat mode to use.

---

## Username Extraction

    python3 PassHarvester.py /data -m combo --extract-users -o ~/wordlist.txt

When scanning combo-list format files (user:password), this flag extracts all
usernames and emails into a separate `_users.txt` file.

**Output:** `~/wordlist_users.txt` containing one username per line.

Useful for:
- User enumeration and credential stuffing
- Building targeted username lists
- Cross-referencing with other breaches

---

## Password Reuse Report

    python3 PassHarvester.py /data -m combo --track-sources --reuse-report -o ~/wordlist.txt

Shows passwords that appear across multiple source files. Requires
`--track-sources` to be enabled so the scanner records which file each
password was found in.

**Output example:**

    Password Reuse Report (found in multiple source files):

        Password123                      (847x across 3 files)
          - breach_dumps/combo_2019.txt
          - breach_dumps/combo_2023.txt
          - logs/auth.log

Highlights credential reuse patterns — valuable for security assessments.

---

## Password Age Estimation

    python3 PassHarvester.py /data -m combo --age-report -o ~/wordlist.txt

Detects year patterns (1970-2030) embedded in passwords and produces a timeline
showing when passwords were likely created.

**Output example:**

    Password Age Estimation:

        2019 : ▓▓▓▓▓▓▓▓                            234
        2020 : ▓▓▓▓▓▓▓▓▓▓▓▓▓                       389
        2021 : ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                  567
        2022 : ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓           812
        2023 : ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓      945
        2024 : ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓ 1,102

Helps you understand how current a breach dump is and whether passwords are
being updated over time.

---

## JSON & CSV Export

### JSON Export

    python3 PassHarvester.py /data -m combo --export-json -o ~/wordlist.txt

Creates `~/wordlist.json` with full metadata:

    {
      "total": 5049,
      "passwords": [
        {
          "password": "Password123",
          "frequency": 847,
          "length": 11,
          "entropy": 3.28,
          "sources": [
            {"file": "breach_dumps/combo_1.txt", "line": 42}
          ]
        }
      ]
    }

The `sources` field is only included when `--track-sources` is enabled.

### CSV Export

    python3 PassHarvester.py /data -m combo --export-csv -o ~/wordlist.txt

Creates `~/wordlist.csv` with columns: password, frequency, length, entropy,
source_file (if tracking). Opens in Excel, Google Sheets, or any spreadsheet tool.

---

## Wordlist Comparison

    python3 PassHarvester.py --compare wordlist1.txt wordlist2.txt

Compares two wordlists and shows:
- Size of each wordlist
- Overlap count and percentage
- Entries unique to each
- Combined unique total
- Top 10 shared passwords

**Use cases:**
- Check if two breach dumps are actually different or reshuffled copies
- Measure how much of your custom wordlist overlaps with rockyou.txt
- Compare before/after filtering results

---

## Wordlist Merging

    python3 PassHarvester.py --merge file1.txt file2.txt file3.txt -o merged.txt

Combines multiple wordlists into one deduplicated file. Supports optional
filtering during merge:

    # Merge with entropy filter and case dedup
    python3 PassHarvester.py --merge a.txt b.txt -o merged.txt \
        --min-entropy 2.5 --dedup-case

    # Merge with policy filter
    python3 PassHarvester.py --merge a.txt b.txt -o merged.txt \
        --policy "min_length:8,require_upper,require_digit"

---

## Password Policy Filtering

    python3 PassHarvester.py /data -m combo \
        --policy "min_length:8,require_upper,require_digit,require_special" \
        -o ~/wordlist.txt

Filters the output to only include passwords meeting specific rules. Applied
as post-processing after scanning.

### Available Policy Rules

    Rule             | Description                    | Example
    -----------------|--------------------------------|-------------------
    min_length:N     | Minimum character count        | min_length:8
    max_length:N     | Maximum character count        | max_length:64
    require_upper    | Must contain uppercase letter  | require_upper
    require_lower    | Must contain lowercase letter  | require_lower
    require_digit    | Must contain a digit           | require_digit
    require_special  | Must contain special character | require_special
    min_entropy:N    | Minimum Shannon entropy        | min_entropy:3.0

Combine multiple rules with commas:

    --policy "min_length:8,max_length:32,require_upper,require_digit"

Useful when you know the target system's password policy — no point cracking
with passwords that wouldn't have been accepted.

---

## Custom Keywords

    python3 PassHarvester.py /data -m credentials \
        --keywords /path/to/my_keywords.txt -o ~/wordlist.txt

Load your own keyword list for the credentials mode instead of the built-in
89 keywords. The file should have one keyword per line. Lines starting with
`#` are treated as comments.

**Example keyword file (my_keywords.txt):**

    # Application-specific password labels
    db_password
    redis_auth
    jwt_secret
    encryption_key
    master_password
    admin_token
    service_account_key

This is useful for targeting specific applications or frameworks that use
non-standard password label names.

---

## File Type & Date Filtering

### Extension Filter (--extensions)

    python3 PassHarvester.py /data -m credentials \
        --extensions ".conf,.ini,.env,.yml,.xml,.log" -o ~/wordlist.txt

Only scans files with the specified extensions. On a messy 100GB directory,
this can cut scan time dramatically by skipping irrelevant file types.

### Depth Limit (--max-depth)

    python3 PassHarvester.py /data -m credentials --max-depth 2 -o ~/wordlist.txt

Controls how deep into subdirectories to scan:
- `--max-depth 1` = only files directly in the root directory
- `--max-depth 2` = root + one level of subdirectories
- No flag = unlimited depth (default)

### Date Filter (--newer-than)

    python3 PassHarvester.py /data -m combo --newer-than 2024-01-01 -o ~/wordlist.txt

Only scans files modified after the specified date. Useful for:
- Processing only new additions to a directory you've scanned before
- Focusing on recent breach dumps
- Ignoring old/stale files

---

## Color Output

Terminal output uses ANSI colors by default for better readability: green for
the progress bar and success messages, cyan for file paths, yellow for warnings,
bold for headers.

### Disable colors

    python3 PassHarvester.py /data --no-color -o ~/wordlist.txt

Disable colors when piping output to a file or using a terminal that doesn't
support ANSI codes. Can also be set in config files with `no_color = true`.

---

## Multilingual Support

### Supported Languages (30+)

The credentials and Wi-Fi modes recognize password labels in:

    Language    | Password Label Examples
    ------------|-----------------------------------------------
    English     | password, passwd, pwd, pass, secret, token
    Chinese     | 密码, 口令, 秘密, 密碼
    Spanish     | contraseña, clave, secreto
    Hindi       | पासवर्ड, कूटशब्द, गुप्त
    Arabic      | كلمة_السر, كلمة_المرور, رمز_المرور
    Portuguese  | senha, segredo, palavra_passe
    Russian     | пароль, секрет, ключ, токен
    Japanese    | パスワード, 暗証番号, 暗号
    German      | passwort, kennwort, geheimnis
    French      | mot_de_passe, mdp, motdepasse
    Korean      | 비밀번호, 암호, 패스워드, 비번
    Turkish     | şifre, parola
    Italian     | parola_d_ordine, segreto
    Vietnamese  | mật_khẩu
    Thai        | รหัสผ่าน, รหัส
    Polish      | hasło
    Dutch       | wachtwoord
    Czech       | heslo
    Greek       | κωδικός, συνθηματικό
    Romanian    | parolă
    Swedish     | lösenord
    Finnish     | salasana
    Danish      | adgangskode
    Norwegian   | passord
    Hungarian   | jelszó
    Ukrainian   | пароль, гасло
    Indonesian  | kata_sandi, sandi
    Persian     | رمز_عبور, گذرواژه
    Hebrew      | סיסמה, סיסמא
    Bengali     | পাসওয়ার্ড
    Urdu        | پاسورڈ
    Swahili     | nenosiri

The general mode uses Unicode-aware matching to catch passwords in any script.

---

## Using with Cracking Tools

### aircrack-ng (Wi-Fi)

    aircrack-ng capture.cap -w ~/wordlist.txt

### hashcat

    # Crack MD5 hashes with wordlist
    hashcat -m 0 hashes.txt ~/wordlist.txt

    # With rules file
    hashcat -m 0 hashes.txt ~/wordlist.txt -r ~/wordlist.rule

    # With mask attack using generated masks
    hashcat -m 0 hashes.txt -a 3 ~/wordlist.hcmask

    # WPA/WPA2
    hashcat -m 22000 handshake.hc22000 ~/wordlist.txt

    # Common modes: -m 0 (MD5), -m 100 (SHA1), -m 1400 (SHA256),
    #   -m 1000 (NTLM), -m 3200 (bcrypt), -m 22000 (WPA)

### John the Ripper

    john --wordlist=~/wordlist.txt hashes.txt
    john --wordlist=~/wordlist.txt --rules hashes.txt
    john --format=raw-md5 --wordlist=~/wordlist.txt hashes.txt

---

## Large-Scale Scanning (100GB+)

### Recommended Command

    python3 PassHarvester.py /breach_directory \
        -m combo -t 8 -o /fast_drive/wordlist.txt --resume --stats

### Why It Scales

- **Line-by-line streaming:** Constant ~1MB memory per file regardless of size
- **SQLite storage:** Handles hundreds of millions of unique passwords on disk
- **No file-size ceiling:** Every file is streamed, no matter how large
- **Incremental flushing:** Passwords written to database every 1MB, not at file end
- **Binary detection:** Binary files skipped by extension + null-byte heuristic
- **Line length cap:** Lines over 4,096 chars skipped (binary garbage)
- **Password length cap:** Extracted strings over 256 chars discarded
- **Auto-save:** Background thread writes wordlist every 30-60 seconds

### Estimated Scan Times

    Mode        | SSD (1 thread) | SSD (8 threads) | HDD (1 thread)
    ------------|----------------|-----------------|----------------
    combo       | 50-100 MB/s    | 200-400 MB/s    | 20-50 MB/s
    credentials | 30-80 MB/s     | 150-300 MB/s    | 15-40 MB/s
    general     | 20-60 MB/s     | 100-250 MB/s    | 10-30 MB/s
    all         | 15-40 MB/s     | 80-200 MB/s     | 8-20 MB/s

100GB at 100 MB/s ≈ 17 minutes. At 20 MB/s (HDD) ≈ 85 minutes.

---

## Progress Bar & Live Monitoring

The progress bar updates every 1MB of data read, even during a single massive file:

    |████████░░░░░░░░░░░░░░░░░░░░░░░░░░░| 12.3 GB/88.43 GB (14%)  1/2 files  4.1 MB/s  Matches: 1,847,293  WL: 847.2 MB  [6m22s < 39m15s]

**Fields explained:**

- **Progress bar** — Byte-level percentage, fills as data is read
- **Bytes** — Data read so far / total size
- **Files** — Files completed / total files
- **MB/s** — Current read throughput
- **Matches** — Total password matches found so far (updates in real-time)
- **WL** — Current size of the wordlist database on disk (shows how large
  the final wordlist will be)
- **Time** — Elapsed time < estimated remaining time

A background timer re-renders the progress bar every 30 seconds even if no new
data has arrived, keeping the elapsed time and ETA fresh.

### Monitoring from a Second Terminal

    # Watch the wordlist grow in real-time
    watch -n 10 'ls -lh ~/Desktop/wordlist.txt ~/Desktop/.passharvester_temp.db 2>/dev/null'

    # Watch disk space usage
    watch -n 30 'df -h /home'

---

## Interrupt Handling & Auto-Save

### Ctrl+C Behavior

| Action | Result |
|--------|--------|
| **First Ctrl+C** | Immediately flushes all passwords to disk, writes wordlist, saves checkpoint. Prints confirmation with password count. |
| **Second Ctrl+C** | Force quits immediately. No save attempt. |

### Background Auto-Save

A background thread automatically saves progress every 30-60 seconds:
- First auto-save fires after 30 seconds
- Subsequent saves every 60 seconds
- Saves happen during file processing, not just between files
- Works even when processing a single 88GB file

This means even a hard crash (power failure, system freeze) preserves most
of your progress. Resume with --resume after rebooting.

### Force-Killing from Another Terminal

If the script becomes unresponsive:

    # Graceful kill
    kill -INT $(pgrep -f PassHarvester)

    # Force kill
    kill -9 $(pgrep -f PassHarvester)

---

## Architecture & How It Works

### Scanning Pipeline

    1. DISCOVER    → Walk directory tree with filters (extensions, depth, date)
    2. FILTER      → Skip binary files (extension + null-byte check)
    3. STREAM      → Read each file line-by-line (1MB buffer)
    4. MATCH       → Apply regex patterns to each line
    5. ENTROPY     → Filter matches by Shannon entropy (if enabled)
    6. FLUSH       → Write matches to SQLite every 1MB (crash-safe)
    7. AUTOSAVE    → Background thread snapshots wordlist every 30-60 seconds
    8. POST-PROC   → Apply exclusions, case dedup, policy filter
    9. OUTPUT      → Write final wordlist + optional exports from SQLite

### Encoding Handling

Each file is tried with these encodings in order:
1. UTF-8
2. UTF-8 with BOM
3. Windows-1252 (CP1252)
4. Latin-1 (ISO 8859-1)

All use `errors='strict'` so encoding mismatches are detected properly.

### Temporary Files

    .passharvester_temp.db               # SQLite database (auto-deleted)
    .passharvester_temp.db-wal           # SQLite WAL journal (auto-deleted)
    .passharvester_temp.db-shm           # SQLite shared memory (auto-deleted)
    .passharvester_checkpoint.json       # Resume checkpoint (auto-deleted)
    .passharvester_state.json            # Incremental state (kept for next run)

---

## Troubleshooting

### "Python version too old"
You need Python 3.9+. Check with `python3 --version`.

### "Permission denied" errors
The script prints warnings and continues. Use `sudo` for system directories.

### Scan is slow
Use `-t 4` or `-t 8` for multithreading. Use `--extensions` to skip irrelevant
files. Use `combo` or `credentials` mode instead of `general`.

### Output too noisy
Use `--min-entropy 2.5`, `--exclude rockyou.txt`, `--dedup-case`, or a targeted
mode instead of `general`.

### System freezes during scan
Use `ionice -c 3 nice -n 19` prefix. Reduce threads to 1. Make sure output is
on a different drive than input if using an external HDD.

### External HDD won't mount after crash
The filesystem was likely corrupted by I/O thrashing. Repair with:

    # For NTFS drives
    sudo ntfsfix /dev/sdb1
    sudo mount -t ntfs-3g /dev/sdb1 "/media/user/External"

    # If the mount point doesn't exist
    sudo mkdir -p "/media/user/External"

### Ctrl+C doesn't stop the script
This should not happen with the latest version. If it does, press Ctrl+C a
second time to force-quit immediately. Alternatively, kill from another terminal:

    kill -9 $(pgrep -f PassHarvester)

### Resume not working
Use the same output path (`-o`) and start directory as the original scan.

### SQLite errors after crash
Delete temp files and start fresh:

    rm /output/dir/.passharvester_temp.db*
    rm /output/dir/.passharvester_checkpoint.json

---

## Examples & Recipes

### Extract passwords from a data breach

    python3 PassHarvester.py /mnt/breach -m combo -t 8 \
        -o ~/breach_wordlist.txt --stats

### Build a wordlist from config files only

    python3 PassHarvester.py /var/www -m credentials \
        --extensions ".conf,.env,.yml,.ini,.xml" -o ~/config_passwords.txt

### Extract Wi-Fi passwords from router backups

    python3 PassHarvester.py ~/router_backups -m wifi -o ~/wifi_passwords.txt

### High-quality filtered wordlist

    python3 PassHarvester.py /data -m all \
        --min-entropy 3.0 --dedup-case \
        --exclude /usr/share/wordlists/rockyou.txt \
        --policy "min_length:8,require_upper,require_digit" \
        -o ~/filtered_wordlist.txt

### Complete cracking toolkit

    python3 PassHarvester.py /breach -m combo -t 8 \
        -f frequency --rules --masks --stats --extract-users \
        --hash-id --age-report -o ~/crack/wordlist.txt

    # Creates:
    #   ~/crack/wordlist.txt           Frequency-sorted wordlist
    #   ~/crack/wordlist.rule          Hashcat rules (34 mutations)
    #   ~/crack/wordlist.hcmask        Hashcat masks (top 100 patterns)
    #   ~/crack/wordlist_users.txt     Extracted usernames
    #   ~/crack/wordlist_stats.txt     Password analysis report

### Security audit with source tracking

    python3 PassHarvester.py /data -m all \
        --track-sources --reuse-report --export-json \
        -o ~/audit/wordlist.txt

### Forensic analysis with metadata

    python3 PassHarvester.py /evidence -m all \
        --track-sources --export-json --export-csv \
        --stats --age-report -o ~/forensics/passwords.txt

### Scan only recent files

    python3 PassHarvester.py /data -m credentials \
        --newer-than 2024-06-01 -o ~/recent_passwords.txt

### Compare two breach dumps

    python3 PassHarvester.py --compare dump_2023.txt dump_2024.txt

### Merge and clean multiple wordlists

    python3 PassHarvester.py --merge list1.txt list2.txt list3.txt \
        --dedup-case --min-entropy 2.5 -o ~/merged_clean.txt

### Scan a large external drive safely

    ionice -c 3 nice -n 19 python3 PassHarvester.py \
        "/media/user/External Drive" \
        -m combo -t 1 -o ~/Desktop/wordlist.txt --resume

### Overnight scan with auto-save

    python3 PassHarvester.py /huge/directory -m combo -t 4 \
        -o ~/wordlist.txt --resume

    # If interrupted or system reboots:
    python3 PassHarvester.py /huge/directory -m combo -t 4 \
        -o ~/wordlist.txt --resume

### Use a config file for repeated scans

    python3 PassHarvester.py --generate-config ~/scanner.ini
    # Edit ~/scanner.ini to your preferences
    python3 PassHarvester.py /data1 --config ~/scanner.ini -o ~/wl1.txt
    python3 PassHarvester.py /data2 --config ~/scanner.ini -o ~/wl2.txt

---

## All Generated Files Reference

When running with all output options enabled, the script generates these files
alongside the main wordlist:

    File                        | Flag            | Description
    ----------------------------|-----------------|-----------------------------------
    wordlist.txt                | (always)        | Main password wordlist
    wordlist.rule               | --rules         | Hashcat mutation rules (34 rules)
    wordlist.hcmask             | --masks         | Hashcat mask patterns (top 100)
    wordlist_users.txt          | --extract-users | Extracted usernames/emails
    wordlist_stats.txt          | --stats         | Password statistics report
    wordlist.json               | --export-json   | JSON export with metadata
    wordlist.csv                | --export-csv    | CSV export with metadata

Temporary files (auto-deleted on completion):

    .passharvester_temp.db               | SQLite password database
    .passharvester_checkpoint.json       | Resume checkpoint

Persistent state files (kept between runs):

    .passharvester_state.json            | Incremental scan state

---

## Legal & Ethical Notice

**This tool is intended exclusively for authorized security testing, penetration
testing, and forensic analysis.**

- Always obtain **written authorization** before scanning directories, systems,
  or networks
- Only use on systems and data you **own** or have **explicit permission** to test
- Comply with all applicable **local, state, national, and international laws**
- Unauthorized access to computer systems and data is **illegal** in most
  jurisdictions and can result in criminal prosecution
- The authors assume **no liability** for misuse of this tool
- By using this software, you agree to use it **responsibly and ethically**

This tool does not perform any network attacks, credential stuffing, or
unauthorized access. It is a local file scanner that extracts text patterns
from files you already have access to.

Use responsibly.

---

*PassHarvester v4.0 — Built for scale, precision, and multilingual coverage.*
