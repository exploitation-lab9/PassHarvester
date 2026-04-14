#!/usr/bin/env python3
r"""
PassHarvester v4.0 - Advanced large-scale password wordlist builder.

Designed to handle 100GB+ data breach directories without running out of memory.
Output is one-entry-per-line plain text, compatible with aircrack-ng, hashcat,
and John the Ripper. Supports multilingual password detection across 30+ languages
and all Unicode scripts.

Usage:
    python PassHarvester.py <start_directory> [options]
    python PassHarvester.py --compare wordlist1.txt wordlist2.txt
    python PassHarvester.py --merge file1.txt file2.txt -o merged.txt

Scan Modes (--mode / -m):
    general      - Unicode-aware: any 6+ char word-character string (all scripts)
    credentials  - Multilingual: values after password labels in 30+ languages
    combo        - Extract passwords from email:password or user:password formats
    hash         - Extract common hash formats (MD5, SHA1, SHA256, bcrypt, NTLM)
    wifi         - Multilingual: Wi-Fi password fields in 20+ languages
    all          - Run all modes at once and merge results

Output Formats (--format / -f):
    plain        - One password per line, sorted alphabetically (default)
    frequency    - Sorted by how often each password was found (most common first)
    potfile      - hashcat .potfile style: <hash>:<password>
    john         - John the Ripper style: <user>:<password>

Additional Exports:
    --export-json    Export passwords with metadata as JSON
    --export-csv     Export passwords with metadata as CSV

Run with -h for full help. Run with --list-modes for mode details.
"""

import os
import sys
import re
import math
import json
import time
import signal
import sqlite3
import argparse
import configparser
import csv
import datetime
from pathlib import Path
from collections import Counter
from typing import List, Set, Dict, Optional, Tuple, Generator
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


# ──────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────────────────────

# File extensions recognized as binary — these are skipped during scanning
BINARY_EXTENSIONS: Set[str] = {
    # Images
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg', '.webp', '.tiff', '.tif',
    # Audio / Video
    '.mp3', '.mp4', '.wav', '.avi', '.mkv', '.flv', '.mov', '.wmv', '.ogg', '.flac',
    # Archives
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar', '.xz', '.zst',
    # Executables / Libraries
    '.exe', '.dll', '.so', '.dylib', '.bin', '.msi', '.deb', '.rpm', '.app',
    # Compiled / Bytecode
    '.pyc', '.pyo', '.class', '.o', '.obj', '.wasm',
    # Documents (binary formats)
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    # Database
    '.db', '.sqlite', '.sqlite3', '.mdb',
    # Disk images / Firmware
    '.iso', '.img', '.vmdk',
    # Fonts
    '.ttf', '.otf', '.woff', '.woff2',
    # Other binary
    '.dat', '.pkl', '.npy', '.npz',
}

# Checkpoint and state file names (stored alongside the output file)
CHECKPOINT_FILE = ".passharvester_checkpoint.json"
INCREMENTAL_STATE_FILE = ".passharvester_state.json"

# Auto-checkpoint triggers
CHECKPOINT_INTERVAL_FILES = 1000    # Save progress every N files
CHECKPOINT_INTERVAL_SECONDS = 60    # Save progress every 60 seconds
FIRST_CHECKPOINT_SECONDS = 30       # First checkpoint after 30 seconds (save early)

# SQLite performance tuning
DB_BATCH_SIZE = 5000                # Insert passwords in batches of this size

# Safety limits for line and password length
MAX_LINE_LENGTH = 4096              # Skip lines longer than this (likely binary garbage)
MAX_PASSWORD_LENGTH = 256           # Skip extracted strings longer than this


# ──────────────────────────────────────────────────────────────────────────────
# COLOR OUTPUT
# ──────────────────────────────────────────────────────────────────────────────

class Color:
    """ANSI color codes for terminal output, with --no-color support."""

    enabled = True

    @classmethod
    def disable(cls):
        """Disable all color output (for --no-color flag or piping to files)."""
        cls.enabled = False

    @classmethod
    def _wrap(cls, code: str, text: str) -> str:
        """Wrap text in ANSI escape codes if color is enabled."""
        if cls.enabled:
            return f"\033[{code}m{text}\033[0m"
        return text

    @classmethod
    def green(cls, text: str) -> str:
        return cls._wrap("32", text)

    @classmethod
    def red(cls, text: str) -> str:
        return cls._wrap("31", text)

    @classmethod
    def yellow(cls, text: str) -> str:
        return cls._wrap("33", text)

    @classmethod
    def cyan(cls, text: str) -> str:
        return cls._wrap("36", text)

    @classmethod
    def bold(cls, text: str) -> str:
        return cls._wrap("1", text)

    @classmethod
    def dim(cls, text: str) -> str:
        return cls._wrap("2", text)


# ──────────────────────────────────────────────────────────────────────────────
# MULTILINGUAL PASSWORD KEYWORDS
# ──────────────────────────────────────────────────────────────────────────────

# Password-related labels across 30+ languages.
# Used by the credentials mode to detect lines like "password=SecretValue"
PASSWORD_KEYWORDS = [
    # English
    "password", "passwd", "pwd", "pass", "passcode",
    "secret", "token", "api_key", "apikey", "auth",
    "credentials", "login_pass", "user_pass",
    # Chinese (Simplified + Traditional)
    "密码", "口令", "秘密", "密碼", "權杖",
    # Spanish
    "contraseña", "clave", "secreto", "contrasenya",
    # Hindi
    "पासवर्ड", "कूटशब्द", "गुप्त",
    # Arabic
    "كلمة_السر", "كلمة_المرور", "رمز_المرور", "سر",
    # Portuguese
    "senha", "segredo", "palavra_passe",
    # Russian
    "пароль", "секрет", "ключ", "токен",
    # Japanese
    "パスワード", "暗証番号", "暗号",
    # German
    "passwort", "kennwort", "geheimnis", "kenncode",
    # French
    "mot_de_passe", "mdp", "motdepasse",
    # Korean
    "비밀번호", "암호", "패스워드", "비번",
    # Turkish
    "şifre", "parola", "sifre",
    # Italian
    "parola_d_ordine", "segreto",
    # Vietnamese
    "mật_khẩu", "mat_khau",
    # Thai
    "รหัสผ่าน", "รหัส",
    # Polish
    "hasło", "haslo",
    # Dutch
    "wachtwoord",
    # Czech / Slovak
    "heslo",
    # Greek
    "κωδικός", "κωδικος", "συνθηματικό",
    # Romanian
    "parolă",
    # Swedish
    "lösenord", "losenord",
    # Finnish
    "salasana",
    # Danish
    "adgangskode",
    # Norwegian
    "passord",
    # Hungarian
    "jelszó", "jelszo",
    # Ukrainian
    "гасло",
    # Indonesian / Malay
    "kata_sandi", "kata_laluan", "sandi",
    # Persian / Farsi
    "رمز_عبور", "گذرواژه",
    # Hebrew
    "סיסמה", "סיסמא",
    # Bengali
    "পাসওয়ার্ড",
    # Urdu
    "پاسورڈ",
    # Swahili
    "nenosiri",
]

# Wi-Fi credential field labels across 20+ languages.
# Used by the wifi mode to detect lines like "psk=WifiPassword123"
WIFI_KEYWORDS = [
    # English / Technical
    "psk", "passphrase", "wpa_passphrase", "network_key",
    "wifi_password", "wifi_pass", "wlan_key", "wlan_password",
    "pre_shared_key", "presharedkey",
    # Chinese
    "wifi密码", "无线密码", "wifi密碼", "無線密碼",
    # Spanish
    "clave_wifi", "contraseña_wifi",
    # Hindi
    "वाईफाई_पासवर्ड",
    # Russian
    "пароль_wifi", "ключ_сети", "пароль_вай_фай",
    # Japanese
    "wifiパスワード", "無線パスワード",
    # German
    "wlan_passwort", "wlan_schlüssel", "netzwerkschlüssel",
    # French
    "mot_de_passe_wifi", "clé_wifi", "cle_wifi",
    # Korean
    "와이파이비밀번호", "wifi비밀번호",
    # Portuguese
    "senha_wifi", "senha_wireless",
    # Turkish
    "wifi_şifresi", "wifi_sifresi",
    # Italian
    "password_wifi", "chiave_wifi",
    # Vietnamese
    "mật_khẩu_wifi", "mat_khau_wifi",
    # Thai
    "รหัสwifi",
    # Dutch
    "wifi_wachtwoord",
    # Polish
    "hasło_wifi", "haslo_wifi",
    # Arabic
    "كلمة_سر_الواي_فاي",
    # Indonesian
    "sandi_wifi", "kata_sandi_wifi",
]


def _build_keyword_pattern(keywords: list) -> str:
    """
    Escape keywords and join into a regex alternation group.
    Sorted longest-first so longer matches take priority.
    """
    escaped = [re.escape(k) for k in keywords]
    escaped.sort(key=len, reverse=True)
    return "|".join(escaped)


# Pre-built keyword patterns for default modes
_PASSWORD_KW_PATTERN = _build_keyword_pattern(PASSWORD_KEYWORDS)
_WIFI_KW_PATTERN = _build_keyword_pattern(WIFI_KEYWORDS)


def load_custom_keywords(filepath: str) -> str:
    """
    Load custom keywords from a file (one per line) and build a regex alternation.
    Lines starting with # are treated as comments and skipped.
    Falls back to built-in password keywords if the file can't be read.
    """
    keywords = []
    encodings = ['utf-8', 'utf-8-sig', 'latin-1']

    for encoding in encodings:
        try:
            with open(filepath, 'r', encoding=encoding, errors='strict') as f:
                keywords = [
                    line.strip() for line in f
                    if line.strip() and not line.startswith('#')
                ]
            break
        except UnicodeDecodeError:
            continue

    if not keywords:
        return _PASSWORD_KW_PATTERN

    return _build_keyword_pattern(keywords)


# ──────────────────────────────────────────────────────────────────────────────
# SCAN MODE PRESETS
# ──────────────────────────────────────────────────────────────────────────────

# Unicode-aware character class for password characters
_UPASS_CLASS = r'[\w@#$%&!^*~]'
_UPASS_NEG_BEHIND = r'(?<![\w@#$%&!^*~])'
_UPASS_NEG_AHEAD = r'(?![\w@#$%&!^*~])'


def build_scan_modes(password_kw_pattern=None, wifi_kw_pattern=None) -> dict:
    """
    Build the scan mode dictionary with regex patterns.
    Accepts optional custom keyword patterns for credentials and wifi modes.
    """
    pw_kw = password_kw_pattern or _PASSWORD_KW_PATTERN
    wf_kw = wifi_kw_pattern or _WIFI_KW_PATTERN

    return {
        "general": {
            "name": "General — Unicode (broad)",
            "description": "Matches any Unicode word-character string of 6+ characters "
                           "(Latin, Cyrillic, CJK, Arabic, Devanagari, etc.).",
            "pattern": _UPASS_NEG_BEHIND + _UPASS_CLASS + r'{6,}' + _UPASS_NEG_AHEAD,
        },
        "credentials": {
            "name": "Credentials — Multilingual (30+ languages)",
            "description": "Captures values after password labels in 30+ languages "
                           "(password, 密码, пароль, contraseña, パスワード, etc.).",
            "pattern": (r'(?i)(?:' + pw_kw +
                        r')[\s_.]*[=:]\s*["\']?(\S+?)["\']?\s*$'),
        },
        "combo": {
            "name": "Combo List (user:pass format)",
            "description": "Extracts the password portion from email:password "
                           "or user:password combo-list formats.",
            "pattern": r'(?:^|[\s,;])[\w.\-+]+(?:@[\w.\-]+)?[:|;](.{4,})$',
        },
        "hash": {
            "name": "Hash Extraction",
            "description": "Extracts common hash formats: MD5 (32 hex), SHA1 (40 hex), "
                           "SHA256 (64 hex), bcrypt ($2b$...), and NTLM-style hashes.",
            "pattern": (r'(?:^|[:\s])(\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'
                        r'|[a-fA-F0-9]{32}(?::[a-fA-F0-9]{32})?'
                        r'|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})(?:$|[:\s])'),
        },
        "wifi": {
            "name": "Wi-Fi Passwords — Multilingual (20+ languages)",
            "description": "Targets Wi-Fi credential fields in 20+ languages "
                           "(PSK, passphrase, wifi密码, wlan_passwort, пароль_wifi, etc.).",
            "pattern": (r'(?i)(?:' + wf_kw +
                        r')[\s_.]*[=:]\s*["\']?(.{8,63}?)["\']?\s*$'),
        },
    }


# Default scan modes using built-in keywords
SCAN_MODES = build_scan_modes()

# Pattern for extracting usernames from combo-list format (captures both parts)
COMBO_USER_PATTERN = re.compile(
    r'(?:^|[\s,;])([\w.\-+]+(?:@[\w.\-]+)?)[:|;](.{4,})$',
    re.MULTILINE
)


# ──────────────────────────────────────────────────────────────────────────────
# HASHCAT RULES
# ──────────────────────────────────────────────────────────────────────────────

# Pre-built mutation rules compatible with hashcat's rule engine
HASHCAT_RULES = [
    # Identity (no change)
    ":",
    # Case toggles
    "l",            # lowercase all
    "u",            # uppercase all
    "c",            # capitalize first, lower rest
    "C",            # lowercase first, upper rest
    "t",            # toggle case of all chars
    "T0",           # toggle case at position 0
    "T1",           # toggle case at position 1
    # Transformations
    "r",            # reverse the word
    "{",            # rotate left
    "}",            # rotate right
    "d",            # duplicate entire word
    # Append common suffixes
    "$1",           # append 1
    "$!",           # append !
    "$0",           # append 0
    "$1$2$3",       # append 123
    "$2$0$2$4",     # append 2024
    "$2$0$2$5",     # append 2025
    "$2$0$2$6",     # append 2026
    "$@",           # append @
    "$#",           # append #
    "$$",           # append $
    # Prepend common prefixes
    "^1",           # prepend 1
    "^!",           # prepend !
    # Leet-speak substitutions
    "sa@",          # a -> @
    "se3",          # e -> 3
    "si1",          # i -> 1
    "so0",          # o -> 0
    "ss$",          # s -> $
    "st7",          # t -> 7
    # Combined mutations
    "c$!",          # capitalize + append !
    "c$1",          # capitalize + append 1
    "l$1$2$3",      # lowercase + append 123
    "u$$",          # uppercase + append $
]

RULE_FILE_HEADER = """# PassHarvester v4.0 - Hashcat Rules File
# Usage: hashcat -m <mode> <hashfile> <wordlist> -r <this_file>
#
# Rules include: case toggles, common suffixes, leet-speak,
# rotations, reverse, duplicate, and combined mutations.
"""


# ──────────────────────────────────────────────────────────────────────────────
# MASK ANALYSIS (for hashcat mask attacks)
# ──────────────────────────────────────────────────────────────────────────────

def generate_mask(password: str) -> str:
    """
    Convert a password into a hashcat mask pattern.

    Each character is replaced with its character class:
        ?l = lowercase letter
        ?u = uppercase letter
        ?d = digit
        ?s = special character

    Example: "Pass1!" -> "?u?l?l?l?d?s"
    """
    mask = []
    for char in password:
        if char.islower():
            mask.append('?l')
        elif char.isupper():
            mask.append('?u')
        elif char.isdigit():
            mask.append('?d')
        else:
            mask.append('?s')
    return ''.join(mask)


def generate_mask_file(store, output_path: str, top_n: int = 100) -> str:
    """
    Analyze all passwords in the store and generate a .hcmask file
    containing the most common password structure patterns.

    Args:
        store: PasswordStore instance with passwords loaded
        output_path: Base path for the output (extension replaced with .hcmask)
        top_n: Number of top mask patterns to include

    Returns:
        Path to the generated .hcmask file
    """
    base, _ = os.path.splitext(output_path)
    mask_path = base + ".hcmask"

    # Count occurrences of each mask pattern
    mask_counter: Counter = Counter()
    for (pwd,) in store.conn.execute("SELECT pwd FROM passwords"):
        mask_counter[generate_mask(pwd)] += 1

    # Write the top patterns to file
    with open(mask_path, 'w', encoding='utf-8') as f:
        f.write("# PassHarvester v4.0 - Hashcat Mask File\n")
        f.write("# Usage: hashcat -m <mode> <hashes> -a 3 <this_file>\n")
        f.write(f"# Top {top_n} most common password patterns\n")
        f.write("#\n")
        for mask, count in mask_counter.most_common(top_n):
            f.write(f"{mask}\n")

    return mask_path


# ──────────────────────────────────────────────────────────────────────────────
# HASH TYPE IDENTIFICATION
# ──────────────────────────────────────────────────────────────────────────────

# Each entry: (regex_pattern, hash_type_name, hashcat_mode_number)
HASH_TYPES = [
    (r'^\$2[aby]\$\d{2}\$.{53}$',                   "bcrypt",              3200),
    (r'^[a-fA-F0-9]{128}$',                          "SHA-512",             1700),
    (r'^[a-fA-F0-9]{64}$',                           "SHA-256",             1400),
    (r'^[a-fA-F0-9]{40}$',                           "SHA-1",              100),
    (r'^[a-fA-F0-9]{32}$',                           "MD5 / NTLM",         0),
    (r'^\$6\$',                                       "sha512crypt",        1800),
    (r'^\$5\$',                                       "sha256crypt",        7400),
    (r'^\$1\$',                                       "md5crypt",           500),
    (r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$',          "NTLM (hash:hash)",   1000),
]


def identify_hash(hash_string: str) -> Optional[Tuple[str, int]]:
    """
    Identify the type of a hash string.

    Returns:
        Tuple of (hash_type_name, hashcat_mode_number), or None if unrecognized.
    """
    cleaned = hash_string.strip()
    for pattern, name, mode in HASH_TYPES:
        if re.match(pattern, cleaned):
            return (name, mode)
    return None


def identify_hashes_in_store(store) -> Dict[str, List[Tuple[str, int]]]:
    """
    Scan all passwords in the store, identify hash types, and group them.

    Returns:
        Dictionary mapping hash type name -> list of (hash_string, hashcat_mode)
    """
    results: Dict[str, List[Tuple[str, int]]] = {}
    for (pwd,) in store.conn.execute("SELECT pwd FROM passwords"):
        identification = identify_hash(pwd)
        if identification:
            name, mode = identification
            if name not in results:
                results[name] = []
            results[name].append((pwd, mode))
    return results


# ──────────────────────────────────────────────────────────────────────────────
# ENTROPY CALCULATION
# ──────────────────────────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """
    Calculate the Shannon entropy of a string in bits per character.

    Higher entropy = more randomness/complexity.
    Typical values: common words ~2.0, passwords ~3.0, random strings ~4.0+
    """
    if not s:
        return 0.0

    length = len(s)
    frequency: Dict[str, int] = {}
    for char in s:
        frequency[char] = frequency.get(char, 0) + 1

    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


# ──────────────────────────────────────────────────────────────────────────────
# PASSWORD POLICY VALIDATOR
# ──────────────────────────────────────────────────────────────────────────────

def parse_policy(policy_string: str) -> dict:
    """
    Parse a policy string into a dictionary of requirements.

    Format: "key:value,key:value,flag,flag"
    Examples:
        "min_length:8,require_upper,require_digit,require_special"
        "min_length:10,max_length:64,min_entropy:3.0"

    Supported keys:
        min_length, max_length     - Character count limits
        require_upper              - Must contain uppercase letter
        require_lower              - Must contain lowercase letter
        require_digit              - Must contain a digit
        require_special            - Must contain a special character
        min_entropy                - Minimum Shannon entropy (bits/char)
    """
    policy = {}
    for part in policy_string.split(','):
        part = part.strip()
        if ':' in part:
            key, value = part.split(':', 1)
            policy[key.strip()] = value.strip()
        else:
            policy[part] = True
    return policy


def password_meets_policy(password: str, policy: dict) -> bool:
    """
    Check if a password meets all requirements in the policy dictionary.

    Returns True if the password passes all checks, False otherwise.
    """
    if 'min_length' in policy and len(password) < int(policy['min_length']):
        return False

    if 'max_length' in policy and len(password) > int(policy['max_length']):
        return False

    if policy.get('require_upper') and not re.search(r'[A-Z]', password):
        return False

    if policy.get('require_lower') and not re.search(r'[a-z]', password):
        return False

    if policy.get('require_digit') and not re.search(r'[0-9]', password):
        return False

    if policy.get('require_special') and not re.search(r'[^a-zA-Z0-9]', password):
        return False

    if 'min_entropy' in policy:
        if shannon_entropy(password) < float(policy['min_entropy']):
            return False

    return True


# ──────────────────────────────────────────────────────────────────────────────
# PROGRESS TRACKER (byte-level with throughput)
# ──────────────────────────────────────────────────────────────────────────────

class ProgressTracker:
    """
    Thread-safe progress tracker with byte-level throughput and ETA.
    Shows a visual progress bar, file count, match count, MB/s, time estimate,
    and the current size of the growing wordlist database.

    Updates in two ways:
    1. update() — called when a file completes (increments file count)
    2. add_bytes() — called during file processing (updates bytes without
       incrementing file count, so the bar moves during large files)

    Also runs a background timer that re-renders every 30 seconds even if
    no new data has arrived, so the elapsed time and ETA stay fresh.
    """

    # How often (in bytes) the streaming function should report progress
    # and check for interrupts. 1MB gives fast Ctrl+C response even on slow HDDs.
    INTRA_FILE_REPORT_INTERVAL = 1 * 1024 * 1024  # every 1 MB

    def __init__(self, total_bytes: int, total_files: int,
                 db_path: str = "", bar_width: int = 35):
        self.total_bytes = total_bytes
        self.total_files = total_files
        self.bar_width = bar_width
        self.db_path = db_path  # Path to temp SQLite database to show its size
        self.bytes_done = 0
        self.files_done = 0
        self.matches = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        self._last_line_length = 0
        self._last_render_time = 0
        self._stopped = False

        # Background timer thread: re-renders every 30 seconds
        self._timer_thread = threading.Thread(target=self._timer_loop, daemon=True)
        self._timer_thread.start()

    def _timer_loop(self) -> None:
        """Background thread that re-renders the progress bar every 30 seconds."""
        while not self._stopped:
            time.sleep(30)
            if self._stopped:
                break
            with self.lock:
                self._render()

    def update(self, file_bytes: int, match_count: int = 0) -> None:
        """Record progress for one completed file."""
        with self.lock:
            self.files_done += 1
            self.bytes_done += file_bytes
            self.matches += match_count
            self._render()

    def add_bytes(self, byte_count: int, match_count: int = 0) -> None:
        """
        Add bytes processed within a file (intra-file progress).
        Called periodically by stream_extract_passwords so the progress bar
        moves while processing large files instead of waiting until the file finishes.
        """
        with self.lock:
            self.bytes_done += byte_count
            self.matches += match_count
            # Throttle rendering to at most once per second during intra-file updates
            now = time.time()
            if now - self._last_render_time >= 1.0:
                self._render()
                self._last_render_time = now

    def _render(self) -> None:
        """Redraw the progress bar on the current terminal line."""
        elapsed = time.time() - self.start_time

        # Calculate percentage
        percent = min(self.bytes_done / self.total_bytes, 1.0) if self.total_bytes else 1.0
        filled = int(self.bar_width * percent)
        bar = Color.green("█" * filled) + Color.dim("░" * (self.bar_width - filled))

        # Throughput in MB/s
        megabytes_per_sec = (self.bytes_done / (1024 * 1024)) / elapsed if elapsed > 0 else 0

        # ETA calculation
        if self.bytes_done > 0 and percent < 1.0:
            eta_seconds = (elapsed / percent) - elapsed
            eta_string = self._format_time(eta_seconds)
        elif percent >= 1.0:
            eta_string = "done"
        else:
            eta_string = "..."

        elapsed_string = self._format_time(elapsed)

        # Get current wordlist database size
        wordlist_size = ""
        if self.db_path:
            try:
                db_size = os.path.getsize(self.db_path)
                wordlist_size = f"  WL: {self._format_bytes(db_size)}"
            except OSError:
                pass

        line = (
            f"\r  |{bar}| "
            f"{self._format_bytes(self.bytes_done)}/{self._format_bytes(self.total_bytes)} "
            f"({percent:.0%})  "
            f"{self.files_done}/{self.total_files} files  "
            f"{megabytes_per_sec:.1f} MB/s  "
            f"Matches: {self.matches:,}{wordlist_size}  "
            f"[{elapsed_string} < {eta_string}]"
        )

        # Pad with spaces to overwrite any leftover characters from previous render
        padding = max(0, self._last_line_length - len(line))
        sys.stdout.write(line + " " * padding)
        sys.stdout.flush()
        self._last_line_length = len(line)

    def finish(self) -> None:
        """Mark progress as complete and move to next line."""
        self._stopped = True
        with self.lock:
            self.bytes_done = self.total_bytes
            self.files_done = self.total_files
            self._render()
        sys.stdout.write("\n")
        sys.stdout.flush()

    @staticmethod
    def _format_time(seconds: float) -> str:
        """Format seconds into a human-readable string."""
        seconds = max(0, seconds)
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            minutes, secs = divmod(int(seconds), 60)
            return f"{minutes}m{secs:02d}s"
        else:
            hours, remainder = divmod(int(seconds), 3600)
            minutes, secs = divmod(remainder, 60)
            return f"{hours}h{minutes:02d}m{secs:02d}s"

    @staticmethod
    def _format_bytes(byte_count: int) -> str:
        """Format byte count into human-readable string."""
        if byte_count < 1024:
            return f"{byte_count} B"
        elif byte_count < 1024 ** 2:
            return f"{byte_count / 1024:.1f} KB"
        elif byte_count < 1024 ** 3:
            return f"{byte_count / (1024**2):.1f} MB"
        else:
            return f"{byte_count / (1024**3):.2f} GB"


# ──────────────────────────────────────────────────────────────────────────────
# PASSWORD STORE (SQLite-backed)
# ──────────────────────────────────────────────────────────────────────────────

class PasswordStore:
    """
    SQLite-backed password storage for memory-efficient deduplication.
    Handles hundreds of millions of entries without exhausting RAM.

    Uses WAL mode for concurrent read/write performance and batched
    inserts for throughput.

    Optional source tracking records which file and line number each
    password was found in (enabled with --track-sources flag).
    """

    def __init__(self, db_path: str, track_sources: bool = False):
        self.db_path = db_path
        self.track_sources = track_sources

        # Connect with autocommit mode for explicit transaction control
        self.conn = sqlite3.connect(db_path, isolation_level=None)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA cache_size=-64000")   # 64MB cache
        self.conn.execute("PRAGMA temp_store=MEMORY")

        # Main password table with frequency counter
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                pwd TEXT PRIMARY KEY,
                freq INTEGER DEFAULT 1
            )
        """)

        # Optional source tracking table
        if track_sources:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS sources (
                    pwd TEXT,
                    src TEXT,
                    line INTEGER
                )
            """)
            self.conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_src_pwd ON sources(pwd)"
            )

        # Batching state — RLock allows the signal handler to safely access
        # the store from the same thread that's already holding the lock
        self._password_batch: List[str] = []
        self._source_batch: List[Tuple[str, str, int]] = []
        self._total_raw = 0
        self.lock = threading.RLock()

    def add_batch(self, passwords: List[str], source_file: str = "",
                  line_numbers: List[int] = None) -> None:
        """
        Add passwords to the pending batch. Automatically flushes to disk
        when the batch reaches DB_BATCH_SIZE.

        Args:
            passwords: List of password strings to add
            source_file: Path to the file these passwords came from
            line_numbers: Line numbers for each password (parallel to passwords list)
        """
        with self.lock:
            self._password_batch.extend(passwords)
            self._total_raw += len(passwords)

            # Track source information if enabled
            if self.track_sources and source_file:
                for i, pwd in enumerate(passwords):
                    line_num = line_numbers[i] if line_numbers and i < len(line_numbers) else 0
                    self._source_batch.append((pwd, source_file, line_num))

            # Flush when batch is full
            if len(self._password_batch) >= DB_BATCH_SIZE:
                self._flush()

    def _flush(self) -> None:
        """Write pending password and source batches to SQLite."""
        if not self._password_batch:
            return

        self.conn.execute("BEGIN")
        try:
            # Upsert passwords: insert new, increment frequency for existing
            self.conn.executemany(
                "INSERT INTO passwords (pwd, freq) VALUES (?, 1) "
                "ON CONFLICT(pwd) DO UPDATE SET freq = freq + 1",
                [(pwd,) for pwd in self._password_batch]
            )

            # Insert source tracking records
            if self._source_batch:
                self.conn.executemany(
                    "INSERT INTO sources (pwd, src, line) VALUES (?, ?, ?)",
                    self._source_batch
                )

            self.conn.execute("COMMIT")
        except Exception:
            self.conn.execute("ROLLBACK")
            raise

        self._password_batch.clear()
        self._source_batch.clear()

    def finalize(self) -> None:
        """Flush any remaining batched passwords to disk."""
        with self.lock:
            self._flush()

    @property
    def total_raw(self) -> int:
        """Total number of raw password matches found (including duplicates)."""
        return self._total_raw

    def restore_raw_count(self, count: int) -> None:
        """Restore the raw count when resuming from a checkpoint."""
        self._total_raw = count

    def unique_count(self) -> int:
        """Count of unique passwords in the store."""
        row = self.conn.execute("SELECT COUNT(*) FROM passwords").fetchone()
        return row[0] if row else 0

    def remove_exclusions(self, exclude_path: str) -> int:
        """
        Remove passwords that appear in an exclusion wordlist.
        The exclusion file is streamed line-by-line so it can be any size.

        Returns the number of passwords removed.
        """
        before = self.unique_count()
        encodings = ['utf-8', 'utf-8-sig', 'latin-1']

        for encoding in encodings:
            try:
                batch = []
                with open(exclude_path, 'r', encoding=encoding, errors='strict') as f:
                    for line in f:
                        stripped = line.strip()
                        if stripped:
                            batch.append((stripped,))
                            if len(batch) >= 10000:
                                self.conn.execute("BEGIN")
                                self.conn.executemany(
                                    "DELETE FROM passwords WHERE pwd = ?", batch
                                )
                                self.conn.execute("COMMIT")
                                batch.clear()

                # Flush remaining batch
                if batch:
                    self.conn.execute("BEGIN")
                    self.conn.executemany(
                        "DELETE FROM passwords WHERE pwd = ?", batch
                    )
                    self.conn.execute("COMMIT")

                return before - self.unique_count()

            except UnicodeDecodeError:
                continue
            except Exception as e:
                print(f"    [Warning] Error reading exclusion file: {e}")
                return before - self.unique_count()

        return before - self.unique_count()

    def apply_case_dedup(self) -> int:
        """
        Remove case-insensitive duplicates, keeping the version with
        the highest frequency count.

        Returns the number of duplicates removed.
        """
        before = self.unique_count()
        self.conn.execute("BEGIN")
        self.conn.execute("""
            DELETE FROM passwords WHERE rowid NOT IN (
                SELECT rowid FROM (
                    SELECT rowid, ROW_NUMBER() OVER (
                        PARTITION BY LOWER(pwd)
                        ORDER BY freq DESC, pwd ASC
                    ) as rn
                    FROM passwords
                ) WHERE rn = 1
            )
        """)
        self.conn.execute("COMMIT")
        return before - self.unique_count()

    def apply_policy(self, policy: dict) -> int:
        """
        Remove passwords that don't meet the specified policy requirements.

        Returns the number of passwords removed.
        """
        before = self.unique_count()
        to_delete = []

        for (pwd,) in self.conn.execute("SELECT pwd FROM passwords"):
            if not password_meets_policy(pwd, policy):
                to_delete.append((pwd,))

        if to_delete:
            self.conn.execute("BEGIN")
            self.conn.executemany("DELETE FROM passwords WHERE pwd = ?", to_delete)
            self.conn.execute("COMMIT")

        return before - self.unique_count()

    def write_output(self, output_path: str, output_format: str) -> int:
        """
        Write the final wordlist to disk in the specified format.

        Returns the number of entries written.
        """
        output_dir = os.path.dirname(os.path.realpath(output_path))
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        # Choose sort order based on format
        if output_format == "frequency":
            query = "SELECT pwd, freq FROM passwords ORDER BY freq DESC, pwd ASC"
        else:
            query = "SELECT pwd, freq FROM passwords ORDER BY pwd ASC"

        count = 0
        with open(output_path, 'w', encoding='utf-8') as out_file:
            for pwd, freq in self.conn.execute(query):
                clean = pwd.strip()
                if not clean:
                    continue

                if output_format == "potfile":
                    out_file.write(f"<hash>:{clean}\n")
                elif output_format == "john":
                    out_file.write(f"user:{clean}\n")
                else:
                    out_file.write(f"{clean}\n")

                count += 1

        return count

    def write_json(self, output_path: str) -> int:
        """
        Export all passwords as a JSON file with metadata.
        Includes frequency, length, entropy, and source files (if tracked).
        """
        base, _ = os.path.splitext(output_path)
        json_path = base + ".json"

        entries = []
        for pwd, freq in self.conn.execute(
            "SELECT pwd, freq FROM passwords ORDER BY freq DESC, pwd ASC"
        ):
            entry = {
                "password": pwd,
                "frequency": freq,
                "length": len(pwd),
                "entropy": round(shannon_entropy(pwd), 2),
            }

            # Add source info if tracking is enabled
            if self.track_sources:
                sources = self.conn.execute(
                    "SELECT src, line FROM sources WHERE pwd = ? LIMIT 10",
                    (pwd,)
                ).fetchall()
                entry["sources"] = [{"file": s, "line": l} for s, l in sources]

            entries.append(entry)

        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(
                {"total": len(entries), "passwords": entries},
                f, indent=2, ensure_ascii=False
            )

        return len(entries)

    def write_csv(self, output_path: str) -> int:
        """
        Export all passwords as a CSV file with metadata.
        Columns: password, frequency, length, entropy, source_file (if tracked).
        """
        base, _ = os.path.splitext(output_path)
        csv_path = base + ".csv"

        count = 0
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Build header
            header = ["password", "frequency", "length", "entropy"]
            if self.track_sources:
                header.append("source_file")
            writer.writerow(header)

            # Write rows
            for pwd, freq in self.conn.execute(
                "SELECT pwd, freq FROM passwords ORDER BY freq DESC"
            ):
                row = [pwd, freq, len(pwd), round(shannon_entropy(pwd), 2)]

                if self.track_sources:
                    source = self.conn.execute(
                        "SELECT src FROM sources WHERE pwd = ? LIMIT 1",
                        (pwd,)
                    ).fetchone()
                    row.append(source[0] if source else "")

                writer.writerow(row)
                count += 1

        return count

    def write_partial_snapshot(self, output_path: str) -> int:
        """
        Write a partial snapshot of all current passwords to disk.
        Called during auto-checkpoints and on interrupt so work is never lost.
        Uses atomic temp file + rename to avoid corrupting the wordlist mid-write.
        """
        output_dir = os.path.dirname(os.path.realpath(output_path))
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

        tmp_path = output_path + ".tmp"
        count = 0

        try:
            with open(tmp_path, 'w', encoding='utf-8') as out:
                for (pwd,) in self.conn.execute(
                    "SELECT pwd FROM passwords ORDER BY pwd ASC"
                ):
                    clean = pwd.strip()
                    if clean:
                        out.write(f"{clean}\n")
                        count += 1

            # Atomic rename — the output file is never in a half-written state
            os.replace(tmp_path, output_path)

        except Exception:
            # Don't let a snapshot failure kill the scan
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        return count

    def get_top_frequencies(self, n: int = 20) -> List[Tuple[str, int]]:
        """Get the top N most frequently found passwords."""
        return self.conn.execute(
            "SELECT pwd, freq FROM passwords ORDER BY freq DESC, pwd ASC LIMIT ?",
            (n,)
        ).fetchall()

    def get_reuse_report(self) -> List[Tuple[str, int, List[str]]]:
        """
        Find passwords that appear across multiple source files.
        Requires --track-sources to be enabled.

        Returns list of (password, frequency, [source_files])
        """
        if not self.track_sources:
            return []

        results = []
        for pwd, freq in self.conn.execute(
            "SELECT pwd, freq FROM passwords WHERE freq > 1 ORDER BY freq DESC LIMIT 50"
        ):
            source_files = list(set(
                row[0] for row in self.conn.execute(
                    "SELECT DISTINCT src FROM sources WHERE pwd = ?", (pwd,)
                )
            ))
            if len(source_files) > 1:
                results.append((pwd, freq, source_files))

        return results

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()

    def destroy(self) -> None:
        """Close connection and delete all database files."""
        self.close()
        for path in [self.db_path, self.db_path + '-wal', self.db_path + '-shm']:
            if os.path.exists(path):
                os.remove(path)


# ──────────────────────────────────────────────────────────────────────────────
# STATISTICS REPORT
# ──────────────────────────────────────────────────────────────────────────────

def generate_statistics(store: PasswordStore) -> str:
    """
    Generate a detailed statistics report for the passwords in the store.
    For datasets over 5 million entries, uses a random sample of 100,000.
    """
    unique_count = store.unique_count()
    if unique_count == 0:
        return "No passwords found — no statistics to generate.\n"

    # For very large datasets, sample to keep analysis fast
    if unique_count > 5_000_000:
        sample_size = 100_000
        passwords = [
            row[0] for row in store.conn.execute(
                f"SELECT pwd FROM passwords ORDER BY RANDOM() LIMIT {sample_size}"
            )
        ]
        header = (f"\n  NOTE: Statistics based on a random sample of {sample_size:,} "
                  f"from {unique_count:,} total entries.\n")
    else:
        passwords = [
            row[0] for row in store.conn.execute(
                "SELECT pwd FROM passwords ORDER BY pwd"
            )
        ]
        header = ""

    top_frequent = store.get_top_frequencies(20)
    return header + _build_stats_report(passwords, top_frequent)


def _build_stats_report(passwords: List[str],
                        top_freq: List[Tuple[str, int]]) -> str:
    """Build the formatted statistics report string."""
    lines: List[str] = []
    total = len(passwords)

    lines.append("")
    lines.append("=" * 70)
    lines.append("  PASSWORD STATISTICS REPORT")
    lines.append("=" * 70)

    # ── Length distribution ──
    lengths = [len(p) for p in passwords]
    sorted_lengths = sorted(lengths)

    lines.append("")
    lines.append(f"  Length: min={min(lengths)}  max={max(lengths)}  "
                 f"avg={sum(lengths)/total:.1f}  median={sorted_lengths[total//2]}")

    buckets = {"1-5": 0, "6-8": 0, "9-12": 0, "13-16": 0, "17-24": 0, "25+": 0}
    for length in lengths:
        if length <= 5: buckets["1-5"] += 1
        elif length <= 8: buckets["6-8"] += 1
        elif length <= 12: buckets["9-12"] += 1
        elif length <= 16: buckets["13-16"] += 1
        elif length <= 24: buckets["17-24"] += 1
        else: buckets["25+"] += 1

    max_bar_width = 30
    max_bucket_count = max(buckets.values()) or 1
    lines.append("")
    for label, count in buckets.items():
        bar_length = int((count / max_bucket_count) * max_bar_width)
        bar = "▓" * bar_length
        percentage = (count / total) * 100
        lines.append(f"    {label:>5s} : {bar:<{max_bar_width}s} {count:>8,d} ({percentage:5.1f}%)")

    # ── Character class analysis ──
    has_lower = sum(1 for p in passwords if re.search(r'[a-z]', p))
    has_upper = sum(1 for p in passwords if re.search(r'[A-Z]', p))
    has_digit = sum(1 for p in passwords if re.search(r'[0-9]', p))
    has_special = sum(1 for p in passwords if re.search(r'[^a-zA-Z0-9]', p))
    mixed_case = sum(1 for p in passwords if re.search(r'[a-z]', p) and re.search(r'[A-Z]', p))
    all_four = sum(
        1 for p in passwords
        if re.search(r'[a-z]', p) and re.search(r'[A-Z]', p)
        and re.search(r'[0-9]', p) and re.search(r'[^a-zA-Z0-9]', p)
    )

    lines.append(f"\n  Character Classes:")
    for label, value in [("Lowercase", has_lower), ("Uppercase", has_upper),
                         ("Digits", has_digit), ("Special", has_special),
                         ("Mixed case", mixed_case), ("All 4", all_four)]:
        lines.append(f"    {label:<14s}: {value:>8,d} ({value/total*100:5.1f}%)")

    # ── Entropy analysis ──
    entropies = [shannon_entropy(p) for p in passwords]
    weak = sum(1 for e in entropies if e < 2.5)
    medium = sum(1 for e in entropies if 2.5 <= e < 3.5)
    strong = sum(1 for e in entropies if e >= 3.5)

    lines.append(f"\n  Entropy: min={min(entropies):.2f}  max={max(entropies):.2f}  "
                 f"avg={sum(entropies)/total:.2f}")
    lines.append(f"    Weak (<2.5)={weak:,}  Medium (2.5-3.5)={medium:,}  Strong (>3.5)={strong:,}")

    # ── Common patterns ──
    ends_digits = sum(1 for p in passwords if re.search(r'\d+$', p))
    ends_special = sum(1 for p in passwords if re.search(r'[^a-zA-Z0-9]$', p))
    starts_upper = sum(1 for p in passwords if p and p[0].isupper())
    has_year = sum(1 for p in passwords if re.search(r'(?:19|20)\d{2}', p))

    lines.append(f"\n  Patterns: ends_digit={ends_digits:,}  ends_special={ends_special:,}  "
                 f"starts_upper={starts_upper:,}  has_year={has_year:,}")

    # ── Top passwords by frequency ──
    if top_freq:
        lines.append(f"\n  Top {len(top_freq)} Most Frequent:")
        for pwd, count in top_freq:
            display = pwd if len(pwd) <= 40 else pwd[:37] + "..."
            lines.append(f"    {count:>8,d}x  {display}")

    lines.append("")
    lines.append("=" * 70)
    lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# AGE ESTIMATION REPORT
# ──────────────────────────────────────────────────────────────────────────────

def generate_age_report(store: PasswordStore) -> str:
    """
    Detect year patterns (19xx, 20xx) in passwords and produce
    a timeline showing estimated password creation dates.
    """
    year_counter: Counter = Counter()
    total_with_years = 0

    for (pwd,) in store.conn.execute("SELECT pwd FROM passwords"):
        years = re.findall(r'(?:19|20)\d{2}', pwd)
        for year_str in years:
            year_int = int(year_str)
            if 1970 <= year_int <= 2030:
                year_counter[year_int] += 1
                total_with_years += 1

    if not year_counter:
        return "  No year patterns found in passwords.\n"

    lines = ["\n  Password Age Estimation (year patterns detected):\n"]
    max_count = max(year_counter.values())

    for year in sorted(year_counter.keys()):
        count = year_counter[year]
        bar_length = min(40, int((count / max_count) * 40))
        bar = "▓" * bar_length
        lines.append(f"    {year} : {bar:<40s} {count:>6,d}")

    lines.append(f"\n    Total passwords with years: {total_with_years:,}\n")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# PASSWORD REUSE REPORT
# ──────────────────────────────────────────────────────────────────────────────

def generate_reuse_report(store: PasswordStore) -> str:
    """
    Show passwords found across multiple source files.
    Requires --track-sources to have been enabled during scanning.
    """
    reuse_data = store.get_reuse_report()

    if not reuse_data:
        return "  No cross-file password reuse detected (enable --track-sources).\n"

    lines = ["\n  Password Reuse Report (found in multiple source files):\n"]

    for pwd, freq, source_files in reuse_data[:30]:
        display = pwd if len(pwd) <= 30 else pwd[:27] + "..."
        lines.append(f"    {display:<32s} ({freq:,}x across {len(source_files)} files)")
        for src in source_files[:5]:
            lines.append(f"      - {src}")
        if len(source_files) > 5:
            lines.append(f"      ... and {len(source_files) - 5} more")

    lines.append("")
    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# CHECKPOINT MANAGER
# ──────────────────────────────────────────────────────────────────────────────

class CheckpointManager:
    """
    Manages save/load of scan progress for resume capability.
    Stores processed file list, scan counts, and raw match total.
    """

    def __init__(self, output_path: str, start_dir: str):
        out_dir = os.path.dirname(os.path.realpath(output_path)) or "."
        os.makedirs(out_dir, exist_ok=True)
        self.checkpoint_path = os.path.join(out_dir, CHECKPOINT_FILE)
        self.start_dir = os.path.realpath(start_dir)
        self.lock = threading.RLock()

    def save(self, processed_files: Set[str], files_scanned: int,
             bytes_processed: int, total_raw: int = 0) -> None:
        """Save current scan progress to disk."""
        data = {
            "start_dir": self.start_dir,
            "processed_files": list(processed_files),
            "files_scanned": files_scanned,
            "bytes_processed": bytes_processed,
            "total_raw": total_raw,
        }
        with self.lock:
            tmp_path = self.checkpoint_path + ".tmp"
            with open(tmp_path, 'w', encoding='utf-8') as f:
                json.dump(data, f)
            os.replace(tmp_path, self.checkpoint_path)

    def load(self) -> Optional[dict]:
        """Load checkpoint if it exists and matches the current scan directory."""
        if not os.path.exists(self.checkpoint_path):
            return None
        try:
            with open(self.checkpoint_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            if data.get("start_dir") != self.start_dir:
                return None
            return data
        except (json.JSONDecodeError, KeyError):
            return None

    def clear(self) -> None:
        """Remove checkpoint file after successful completion."""
        if os.path.exists(self.checkpoint_path):
            os.remove(self.checkpoint_path)


# ──────────────────────────────────────────────────────────────────────────────
# INCREMENTAL STATE TRACKER
# ──────────────────────────────────────────────────────────────────────────────

class IncrementalState:
    """
    Tracks file modification times for incremental scanning.
    On subsequent runs with --incremental, only files that have been
    modified since the last scan are processed.
    """

    def __init__(self, output_path: str):
        out_dir = os.path.dirname(os.path.realpath(output_path)) or "."
        self.state_path = os.path.join(out_dir, INCREMENTAL_STATE_FILE)
        self.mtimes: Dict[str, float] = {}
        self._load()

    def _load(self) -> None:
        """Load previous state from disk if it exists."""
        if os.path.exists(self.state_path):
            try:
                with open(self.state_path, 'r', encoding='utf-8') as f:
                    self.mtimes = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.mtimes = {}

    def save(self) -> None:
        """Save current state to disk."""
        tmp_path = self.state_path + ".tmp"
        with open(tmp_path, 'w', encoding='utf-8') as f:
            json.dump(self.mtimes, f)
        os.replace(tmp_path, self.state_path)

    def is_modified(self, filepath: str) -> bool:
        """Check if a file has been modified since the last scan."""
        try:
            current_mtime = os.path.getmtime(filepath)
        except OSError:
            return True  # If we can't stat it, assume it's new

        last_mtime = self.mtimes.get(os.path.realpath(filepath))
        return last_mtime is None or current_mtime > last_mtime

    def mark_processed(self, filepath: str) -> None:
        """Record the current modification time of a processed file."""
        try:
            self.mtimes[os.path.realpath(filepath)] = os.path.getmtime(filepath)
        except OSError:
            pass


# ──────────────────────────────────────────────────────────────────────────────
# CORE SCANNING FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

def is_binary_file(file_path: str) -> bool:
    """
    Determine if a file is likely binary using two checks:
    1. Known binary file extension
    2. Null-byte heuristic (check first 8KB for null bytes)
    """
    # Fast path: check extension
    extension = Path(file_path).suffix.lower()
    if extension in BINARY_EXTENSIONS:
        return True

    # Heuristic: read first 8KB and look for null bytes
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(8192)
            if b'\x00' in chunk:
                return True
    except (PermissionError, OSError):
        pass

    return False


def prescan_directory(root_dir: str, extensions: Optional[Set[str]] = None,
                      max_depth: Optional[int] = None,
                      newer_than: Optional[float] = None,
                      incremental_state: Optional[IncrementalState] = None
                      ) -> Tuple[int, int, List[Tuple[str, int]]]:
    """
    Prescan the directory tree with filtering to count files and total bytes.

    Args:
        root_dir: Root directory to scan
        extensions: If set, only include files with these extensions
        max_depth: Maximum directory recursion depth (None = unlimited)
        newer_than: Only include files modified after this timestamp
        incremental_state: If set, only include files modified since last scan

    Returns:
        Tuple of (total_files, total_bytes, file_list)
        where file_list is [(file_path, file_size), ...]
    """
    files: List[Tuple[str, int]] = []
    total_bytes = 0
    root_depth = len(Path(root_dir).resolve().parts)

    try:
        for dirpath, dirnames, filenames in os.walk(root_dir):
            # Check depth limit
            if max_depth is not None:
                current_depth = len(Path(dirpath).resolve().parts) - root_depth
                if current_depth >= max_depth:
                    dirnames.clear()  # Don't descend further
                    continue

            dirnames.sort()

            for filename in filenames:
                full_path = os.path.join(dirpath, filename)

                # Extension filter
                if extensions:
                    ext = Path(filename).suffix.lower()
                    if ext not in extensions:
                        continue

                try:
                    stat_info = os.stat(full_path)

                    # Date filter
                    if newer_than and stat_info.st_mtime < newer_than:
                        continue

                    # Incremental filter
                    if incremental_state and not incremental_state.is_modified(full_path):
                        continue

                    files.append((full_path, stat_info.st_size))
                    total_bytes += stat_info.st_size

                except OSError:
                    continue

    except Exception as e:
        print(f"  Error during directory traversal: {e}")

    return len(files), total_bytes, files


def stream_extract_passwords(file_path: str, patterns: List[re.Pattern],
                             min_entropy: float,
                             track_sources: bool = False,
                             progress: Optional[ProgressTracker] = None,
                             stop_event: Optional[threading.Event] = None,
                             store: Optional['PasswordStore'] = None
                             ) -> Tuple[List[str], int, List[int]]:
    """
    Stream a file line-by-line and extract strings matching the patterns.
    Returns (matches, remaining_bytes, line_numbers).

    If a store is provided, matches are flushed to the database every 1MB
    instead of accumulating in memory. This ensures that for large files
    (e.g. 88GB), passwords are saved incrementally and available for
    checkpoint snapshots at any time — not just when the file finishes.

    If a ProgressTracker is provided, reports bytes and match count every
    1MB so the progress bar updates during large files.

    If a stop_event is provided (threading.Event), the loop checks it every
    1MB and breaks out early when Ctrl+C is pressed.
    """
    matches: List[str] = []
    line_numbers: List[int] = []
    bytes_read = 0
    bytes_since_report = 0
    matches_since_report = 0  # Track match count for progress updates
    encodings = ['utf-8', 'utf-8-sig', 'cp1252', 'latin-1']

    for encoding in encodings:
        try:
            line_num = 0
            with open(file_path, 'r', encoding=encoding, errors='strict',
                       buffering=1024 * 1024) as f:
                for line in f:
                    line_num += 1
                    line_bytes = len(line.encode(encoding, errors='replace'))
                    bytes_read += line_bytes
                    bytes_since_report += line_bytes

                    # Every ~1MB: report progress, flush matches, check interrupt
                    if bytes_since_report >= ProgressTracker.INTRA_FILE_REPORT_INTERVAL:

                        # Flush accumulated matches to the database so they
                        # survive auto-checkpoints and Ctrl+C saves
                        if store and matches:
                            store.add_batch(
                                matches,
                                file_path if track_sources else "",
                                line_numbers if track_sources else None
                            )
                            matches = []
                            line_numbers = []

                        # Update progress bar with bytes and matches found
                        if progress:
                            progress.add_bytes(bytes_since_report, matches_since_report)
                        bytes_since_report = 0
                        matches_since_report = 0

                        # Check if user pressed Ctrl+C
                        if stop_event and stop_event.is_set():
                            break

                    # Skip absurdly long lines (likely binary garbage)
                    if len(line) > MAX_LINE_LENGTH:
                        continue

                    for pattern in patterns:
                        for match in pattern.findall(line):
                            cleaned = match.strip()
                            if cleaned and len(cleaned) <= MAX_PASSWORD_LENGTH:
                                if min_entropy <= 0 or shannon_entropy(cleaned) >= min_entropy:
                                    matches.append(cleaned)
                                    matches_since_report += 1
                                    if track_sources:
                                        line_numbers.append(line_num)

            # Return any remaining unflushed matches and unreported bytes
            return (matches, bytes_since_report, line_numbers)

        except UnicodeDecodeError:
            bytes_read = 0
            bytes_since_report = 0
            matches_since_report = 0
            matches = []
            line_numbers = []
            continue
        except PermissionError:
            try:
                remaining = os.path.getsize(file_path) - (bytes_read - bytes_since_report)
            except OSError:
                remaining = 0
            return ([], max(0, remaining), [])
        except Exception:
            try:
                remaining = os.path.getsize(file_path) - (bytes_read - bytes_since_report)
            except OSError:
                remaining = 0
            return ([], max(0, remaining), [])

    return ([], bytes_since_report, [])


def extract_usernames(file_path: str) -> List[str]:
    """
    Extract usernames/emails from combo-list format files.
    Returns a list of username strings found before the : or ; delimiter.
    """
    users = []
    encodings = ['utf-8', 'utf-8-sig', 'cp1252', 'latin-1']

    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding, errors='strict') as f:
                for line in f:
                    match = COMBO_USER_PATTERN.search(line)
                    if match:
                        users.append(match.group(1))
            return users
        except UnicodeDecodeError:
            continue
        except Exception:
            return users

    return users


def process_file(file_path: str, patterns: List[re.Pattern],
                 resolved_output: str, min_entropy: float,
                 file_size: int, track_sources: bool = False,
                 progress: Optional[ProgressTracker] = None,
                 stop_event: Optional[threading.Event] = None,
                 store: Optional['PasswordStore'] = None
                 ) -> Tuple[str, List[str], int, bool, List[int]]:
    """
    Process a single file: skip binary/output, extract passwords.

    If a store is provided, matches are flushed to the database incrementally
    during processing (every ~1MB). Only unflushed remainder matches are returned.

    Returns:
        (file_path, remaining_matches, remaining_bytes, was_scanned, remaining_line_nums)
    """
    # Skip the output file itself
    if os.path.realpath(file_path) == resolved_output:
        return (file_path, [], file_size, False, [])

    # Skip binary files
    if is_binary_file(file_path):
        return (file_path, [], file_size, False, [])

    # Extract passwords — store handles incremental flushing during the file
    matches, remaining_bytes, line_nums = stream_extract_passwords(
        file_path, patterns, min_entropy, track_sources, progress, stop_event, store
    )

    return (file_path, matches, remaining_bytes or file_size, True, line_nums)


# ──────────────────────────────────────────────────────────────────────────────
# WORDLIST COMPARISON
# ──────────────────────────────────────────────────────────────────────────────

def compare_wordlists(path1: str, path2: str) -> None:
    """
    Compare two wordlists and display overlap statistics.
    Shows: size of each, overlap count, unique-to-each, and percentage overlap.
    """
    print(f"\n  Comparing wordlists:")
    print(f"    A: {path1}")
    print(f"    B: {path2}\n")

    def load_wordlist(path):
        """Load a wordlist into a set, trying multiple encodings."""
        words = set()
        for encoding in ['utf-8', 'latin-1']:
            try:
                with open(path, 'r', encoding=encoding, errors='strict') as f:
                    for line in f:
                        word = line.strip()
                        if word:
                            words.add(word)
                return words
            except UnicodeDecodeError:
                continue
        return words

    set_a = load_wordlist(path1)
    set_b = load_wordlist(path2)

    overlap = set_a & set_b
    only_a = set_a - set_b
    only_b = set_b - set_a
    combined = set_a | set_b
    overlap_pct = (len(overlap) / len(combined) * 100) if combined else 0

    print(f"  Results:")
    print(f"    Wordlist A         : {len(set_a):>12,d} entries")
    print(f"    Wordlist B         : {len(set_b):>12,d} entries")
    print(f"    Overlap            : {len(overlap):>12,d} entries ({overlap_pct:.1f}%)")
    print(f"    Unique to A        : {len(only_a):>12,d} entries")
    print(f"    Unique to B        : {len(only_b):>12,d} entries")
    print(f"    Combined unique    : {len(combined):>12,d} entries\n")

    if overlap:
        sample = sorted(overlap)[:10]
        print(f"  Top 10 shared passwords:")
        for pwd in sample:
            print(f"    {pwd}")

    print("")


# ──────────────────────────────────────────────────────────────────────────────
# WORDLIST MERGING
# ──────────────────────────────────────────────────────────────────────────────

def merge_wordlists(paths: List[str], output_path: str,
                    dedup_case: bool = False, min_entropy: float = 0.0,
                    policy: Optional[dict] = None) -> None:
    """
    Merge multiple wordlist files into one deduplicated output file.
    Supports optional entropy filtering, case dedup, and policy filtering.
    """
    print(f"\n  Merging {len(paths)} wordlists into: {output_path}\n")

    passwords: Set[str] = set()
    total_loaded = 0

    for path in paths:
        count = 0
        for encoding in ['utf-8', 'latin-1']:
            try:
                with open(path, 'r', encoding=encoding, errors='strict') as f:
                    for line in f:
                        word = line.strip()
                        if not word:
                            continue

                        # Apply entropy filter
                        if min_entropy > 0 and shannon_entropy(word) < min_entropy:
                            continue

                        # Apply policy filter
                        if policy and not password_meets_policy(word, policy):
                            continue

                        passwords.add(word)
                        count += 1

                break  # Successfully read with this encoding
            except UnicodeDecodeError:
                continue

        print(f"    Loaded {count:,} from {path}")
        total_loaded += count

    # Apply case-insensitive deduplication if requested
    if dedup_case:
        seen_lower: Dict[str, str] = {}
        for pwd in sorted(passwords):
            lower = pwd.lower()
            if lower not in seen_lower:
                seen_lower[lower] = pwd
        passwords = set(seen_lower.values())

    # Write output
    output_dir = os.path.dirname(os.path.realpath(output_path))
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    final_list = sorted(passwords)
    with open(output_path, 'w', encoding='utf-8') as f:
        for pwd in final_list:
            f.write(f"{pwd}\n")

    print(f"\n  Total loaded      : {total_loaded:,}")
    print(f"  Unique after merge: {len(final_list):,}")
    print(f"  Written to        : {output_path}\n")


# ──────────────────────────────────────────────────────────────────────────────
# CONFIG FILE SUPPORT
# ──────────────────────────────────────────────────────────────────────────────

def load_config(config_path: str) -> dict:
    """
    Load scanner settings from an INI-format config file.
    Returns a dictionary of setting name -> value.
    """
    config = configparser.ConfigParser()
    config.read(config_path)

    settings = {}

    if 'scanner' in config:
        section = config['scanner']

        # String settings
        for key in ['mode', 'output', 'pattern', 'format', 'exclude',
                     'extensions', 'keywords', 'policy']:
            if key in section:
                settings[key] = section[key]

        # Float settings
        for key in ['min_entropy']:
            if key in section:
                settings[key] = float(section[key])

        # Integer settings
        for key in ['threads', 'max_depth']:
            if key in section:
                settings[key] = int(section[key])

        # Boolean settings
        for key in ['verbose', 'stats', 'rules', 'dedup_case', 'resume',
                     'no_color', 'track_sources', 'extract_users', 'masks',
                     'hash_id', 'reuse_report', 'age_report', 'incremental',
                     'export_json', 'export_csv']:
            if key in section:
                settings[key] = section.getboolean(key)

    return settings


def generate_sample_config(path: str) -> None:
    """Write a sample config file with all available options documented."""
    sample_content = """\
[scanner]
# ── Scan Mode ──
# Options: general, credentials, combo, hash, wifi, all
mode = general

# Custom regex pattern (overrides mode if set)
# pattern = (?:password|pwd)\\s*[=:]\\s*(\\S+)

# Custom keyword file for credentials/wifi mode (one keyword per line)
# keywords = /path/to/custom_keywords.txt

# ── Output ──
output = wordlist.txt

# Output format: plain, frequency, potfile, john
format = plain

# Generate hashcat rules file (.rule)
rules = false

# Generate hashcat mask file (.hcmask)
masks = false

# Generate password statistics report
stats = false

# Export as JSON with metadata
export_json = false

# Export as CSV with metadata
export_csv = false

# ── Filtering ──
# Minimum Shannon entropy in bits/char (0 = disabled, suggested: 2.5-3.0)
min_entropy = 0

# Case-insensitive deduplication
dedup_case = false

# Exclusion wordlist path (subtract these passwords from results)
# exclude = /path/to/rockyou.txt

# File extensions to scan (comma-separated, e.g. .txt,.conf,.env)
# extensions = .txt,.conf,.env,.log,.yml,.xml

# Maximum directory recursion depth
# max_depth = 5

# Only scan files modified after this date (YYYY-MM-DD)
# newer_than = 2024-01-01

# Password policy filter (e.g. min_length:8,require_upper,require_digit)
# policy = min_length:8,require_upper,require_digit,require_special

# ── Performance ──
# Number of parallel scanning threads
threads = 4

# Resume from last checkpoint on interrupt
resume = false

# Only scan files modified since last run
incremental = false

# ── Analysis ──
# Track which file each password came from
track_sources = false

# Extract usernames from combo lists into separate file
extract_users = false

# Identify hash types and show hashcat mode numbers
hash_id = false

# Show passwords found across multiple source files
reuse_report = false

# Estimate password ages from year patterns
age_report = false

# ── Display ──
# Print per-file progress (disables progress bar)
verbose = false

# Disable color output
no_color = false
"""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(sample_content)
    print(f"Sample config written to: {path}")


# ──────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER
# ──────────────────────────────────────────────────────────────────────────────

def scan_directory(
    start_path: str,
    output_path: str,
    patterns: List[re.Pattern],
    mode_name: str = "",
    verbose: bool = False,
    num_threads: int = 1,
    min_entropy: float = 0.0,
    output_format: str = "plain",
    dedup_case: bool = False,
    show_stats: bool = False,
    generate_rules: bool = False,
    generate_masks: bool = False,
    exclude_path: str = "",
    enable_resume: bool = False,
    track_sources: bool = False,
    extract_users: bool = False,
    hash_id: bool = False,
    reuse_report: bool = False,
    age_report: bool = False,
    export_json: bool = False,
    export_csv: bool = False,
    extensions: Optional[Set[str]] = None,
    max_depth: Optional[int] = None,
    newer_than: Optional[float] = None,
    incremental: bool = False,
    policy: Optional[str] = None,
) -> None:
    """
    Main scanning orchestrator. Discovers files, scans them for passwords,
    applies post-processing filters, and writes output files.
    """
    resolved_output = os.path.realpath(output_path)

    # SQLite temp database alongside output
    db_dir = os.path.dirname(resolved_output) or "."
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, ".passharvester_temp.db")

    # ── Print scan configuration ──
    print(f"\n  {Color.bold('PassHarvester v4.0')}")
    print(f"  Starting scan from : {Color.cyan(start_path)}")
    print(f"  Scan mode          : {mode_name}")
    print(f"  Output             : {resolved_output}")
    print(f"  Format             : {output_format}")
    print(f"  Threads            : {num_threads}")
    if min_entropy > 0:
        print(f"  Min entropy        : {min_entropy:.2f}")
    if dedup_case:
        print(f"  Case dedup         : yes")
    if extensions:
        print(f"  Extensions         : {', '.join(sorted(extensions))}")
    if max_depth is not None:
        print(f"  Max depth          : {max_depth}")
    if newer_than:
        date_str = datetime.datetime.fromtimestamp(newer_than).strftime('%Y-%m-%d')
        print(f"  Newer than         : {date_str}")
    if incremental:
        print(f"  Incremental        : yes")
    if track_sources:
        print(f"  Source tracking     : yes")
    if policy:
        print(f"  Policy filter      : {policy}")

    # ── Discover files ──
    incremental_state = IncrementalState(output_path) if incremental else None

    print("\n  Discovering files...")
    total_files, total_bytes, file_list = prescan_directory(
        start_path, extensions, max_depth, newer_than, incremental_state
    )
    print(f"  Found {total_files:,} files ({ProgressTracker._format_bytes(total_bytes)})\n")

    if total_files == 0:
        print("  No files found.")
        # Create empty output file so downstream tools don't break
        output_dir = os.path.dirname(resolved_output)
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        open(resolved_output, 'w').close()
        return

    # ── Resume support ──
    checkpoint_manager = CheckpointManager(output_path, start_path)
    processed_files: Set[str] = set()
    resumed_scanned = 0
    resumed_bytes = 0
    resumed_raw = 0

    if enable_resume:
        checkpoint = checkpoint_manager.load()
        if checkpoint:
            processed_files = set(checkpoint["processed_files"])
            resumed_scanned = checkpoint.get("files_scanned", 0)
            resumed_bytes = checkpoint.get("bytes_processed", 0)
            resumed_raw = checkpoint.get("total_raw", 0)

            # Filter out already-processed files
            file_list = [(f, s) for f, s in file_list if f not in processed_files]
            print(f"  Resuming: {len(processed_files):,} done, "
                  f"{len(file_list):,} remaining.\n")
        else:
            print("  No checkpoint — fresh start.\n")
            if os.path.exists(db_path):
                os.remove(db_path)
    else:
        if os.path.exists(db_path):
            os.remove(db_path)

    # ── Initialize password store ──
    store = PasswordStore(db_path, track_sources)
    if resumed_raw > 0:
        store.restore_raw_count(resumed_raw)

    # Username extraction set
    user_set: Set[str] = set()

    # Progress bar (disabled in verbose mode)
    progress = None if verbose else ProgressTracker(total_bytes, total_files, db_path)

    # ── Graceful interrupt handler ──
    # First Ctrl+C: immediately flush passwords and save checkpoint, then stop
    # Second Ctrl+C: force immediate exit (no save attempt)
    interrupted = threading.Event()
    _ctrl_c_count = [0]  # mutable counter in list so closure can modify it

    def signal_handler(sig, frame):
        _ctrl_c_count[0] += 1
        if _ctrl_c_count[0] >= 2:
            print(f"\n\n  {Color.red('Force quit! Exiting immediately.')}")
            if progress:
                progress._stopped = True
            os._exit(1)
        interrupted.set()
        print(f"\n\n  {Color.yellow('Interrupt! Saving...')} ", end="", flush=True)

        # Immediately flush and save — don't wait for the scan loop to exit
        try:
            store.finalize()
            store.write_partial_snapshot(resolved_output)
            checkpoint_manager.save(
                processed_files, files_scanned,
                bytes_processed, store.total_raw
            )
            unique_so_far = store.unique_count()
            print(Color.green(f"Done! {unique_so_far:,} passwords saved."))
            print(f"  Wordlist: {resolved_output}")
            print(f"  {Color.yellow('Press Ctrl+C again to exit, or wait for clean shutdown.')}")
        except Exception as e:
            print(f"Save error: {e}")

    original_handler = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, signal_handler)

    # ── Scanning loop ──
    files_scanned = resumed_scanned
    bytes_processed = resumed_bytes
    last_checkpoint_time = time.time()
    files_since_checkpoint = 0
    first_checkpoint_done = False  # Use shorter interval for first save

    # Background auto-save thread: saves checkpoint every 60 seconds even
    # mid-file, so progress is never lost on crash or power failure.
    _autosave_stop = threading.Event()

    def _autosave_loop():
        """Periodically flush and save during long files."""
        # Wait for first checkpoint interval before starting
        _autosave_stop.wait(FIRST_CHECKPOINT_SECONDS)
        while not _autosave_stop.is_set():
            try:
                store.finalize()
                store.write_partial_snapshot(resolved_output)
                checkpoint_manager.save(
                    processed_files, files_scanned,
                    bytes_processed, store.total_raw
                )
            except Exception:
                pass
            _autosave_stop.wait(CHECKPOINT_INTERVAL_SECONDS)

    autosave_thread = threading.Thread(target=_autosave_loop, daemon=True)
    autosave_thread.start()

    try:
        if num_threads > 1:
            # ── Multithreaded scanning ──
            with ThreadPoolExecutor(max_workers=num_threads) as executor:
                futures = {
                    executor.submit(
                        process_file, fp, patterns, resolved_output,
                        min_entropy, sz, track_sources, progress, interrupted, store
                    ): (fp, sz)
                    for fp, sz in file_list
                }

                for future in as_completed(futures):
                    if interrupted.is_set():
                        executor.shutdown(wait=False, cancel_futures=True)
                        break

                    orig_fp, orig_sz = futures[future]
                    file_path, matches, remaining_bytes, was_scanned, line_nums = future.result()
                    processed_files.add(file_path)
                    bytes_processed += orig_sz  # Use known file size for accurate tracking

                    if was_scanned:
                        files_scanned += 1
                        # Flush any remaining matches not yet written to the store
                        if matches:
                            store.add_batch(
                                matches,
                                file_path if track_sources else "",
                                line_nums
                            )

                        # Extract usernames if requested
                        if extract_users:
                            try:
                                user_set.update(extract_usernames(file_path))
                            except Exception:
                                pass

                    # Update display — remaining_bytes is the bytes NOT yet reported
                    # via add_bytes() during intra-file progress
                    if verbose and was_scanned:
                        match_count = len(matches) if matches else 0
                        print(f"  {file_path}  -> {match_count} matches")
                    elif progress:
                        progress.update(remaining_bytes, len(matches) if matches else 0)

                    # Auto-checkpoint — first one fires after 30 seconds, then every 60
                    files_since_checkpoint += 1
                    now = time.time()
                    checkpoint_interval = FIRST_CHECKPOINT_SECONDS if not first_checkpoint_done else CHECKPOINT_INTERVAL_SECONDS
                    if (files_since_checkpoint >= CHECKPOINT_INTERVAL_FILES or
                            now - last_checkpoint_time >= checkpoint_interval):
                        store.finalize()
                        store.write_partial_snapshot(resolved_output)
                        checkpoint_manager.save(
                            processed_files, files_scanned,
                            bytes_processed, store.total_raw
                        )
                        files_since_checkpoint = 0
                        last_checkpoint_time = now
                        first_checkpoint_done = True

        else:
            # ── Single-threaded scanning ──
            for file_path, file_size in file_list:
                if interrupted.is_set():
                    break

                fp, matches, remaining_bytes, was_scanned, line_nums = process_file(
                    file_path, patterns, resolved_output,
                    min_entropy, file_size, track_sources, progress, interrupted, store
                )
                processed_files.add(fp)
                bytes_processed += file_size  # Use known file size for accurate tracking

                if was_scanned:
                    files_scanned += 1
                    # Flush any remaining matches not yet written to the store
                    # (the streaming function flushes every 1MB; this catches the tail)
                    if matches:
                        store.add_batch(
                            matches,
                            fp if track_sources else "",
                            line_nums
                        )

                    # Extract usernames if requested
                    if extract_users:
                        try:
                            user_set.update(extract_usernames(fp))
                        except Exception:
                            pass

                # Update display — remaining_bytes is the bytes NOT yet reported
                # via add_bytes() during intra-file progress
                if verbose and was_scanned:
                    match_count = len(matches) if matches else 0
                    print(f"  {fp}  -> {match_count} matches")
                elif progress:
                    progress.update(remaining_bytes, len(matches) if matches else 0)

                # Auto-checkpoint — first one fires after 30 seconds, then every 60
                files_since_checkpoint += 1
                now = time.time()
                checkpoint_interval = FIRST_CHECKPOINT_SECONDS if not first_checkpoint_done else CHECKPOINT_INTERVAL_SECONDS
                if (files_since_checkpoint >= CHECKPOINT_INTERVAL_FILES or
                        now - last_checkpoint_time >= checkpoint_interval):
                    store.finalize()
                    store.write_partial_snapshot(resolved_output)
                    checkpoint_manager.save(
                        processed_files, files_scanned,
                        bytes_processed, store.total_raw
                    )
                    files_since_checkpoint = 0
                    last_checkpoint_time = now
                    first_checkpoint_done = True

    except Exception as e:
        print(f"\n  Error during scan: {e}")

    # Finish progress bar and stop background threads
    _autosave_stop.set()
    if progress:
        progress.finish()

    # Restore original signal handler
    signal.signal(signal.SIGINT, original_handler)

    # Flush remaining batched passwords
    store.finalize()

    # If interrupted, the signal handler already saved — just confirm
    if interrupted.is_set():
        # Signal handler already flushed and saved, but do a final save
        # in case more passwords were found between the handler and here
        store.write_partial_snapshot(resolved_output)
        checkpoint_manager.save(
            processed_files, files_scanned,
            bytes_processed, store.total_raw
        )
        unique_so_far = store.unique_count()
        print(f"  Final save: {unique_so_far:,} passwords in: {resolved_output}")

    # ── Post-processing ──

    # Exclusion wordlist
    excluded_count = 0
    if exclude_path:
        print(f"\n  Applying exclusion list...")
        excluded_count = store.remove_exclusions(exclude_path)
        print(f"    Removed {excluded_count:,} entries.")

    # Case-insensitive deduplication
    dedup_count = 0
    if dedup_case:
        dedup_count = store.apply_case_dedup()
        print(f"  Case dedup removed {dedup_count:,} entries.")

    # Password policy filter
    policy_count = 0
    if policy:
        parsed_policy = parse_policy(policy) if isinstance(policy, str) else policy
        policy_count = store.apply_policy(parsed_policy)
        print(f"  Policy filter removed {policy_count:,} entries.")

    # ── Write output ──
    try:
        written = store.write_output(resolved_output, output_format)

        print(f"\n  {'-' * 60}")
        print(f"  {Color.green('Wordlist written to:')} {resolved_output}")
        print(f"\n  {Color.bold('── Scan Summary ──')}")
        print(f"    Files discovered    : {total_files:,}")
        print(f"    Files scanned       : {files_scanned:,}")
        print(f"    Data processed      : {ProgressTracker._format_bytes(bytes_processed)}")
        print(f"    Raw matches         : {store.total_raw:,}")
        print(f"    Unique saved        : {Color.green(f'{written:,}')}")
        if excluded_count:
            print(f"    Excluded            : {excluded_count:,}")
        if dedup_count:
            print(f"    Case dedup removed  : {dedup_count:,}")
        if policy_count:
            print(f"    Policy filtered     : {policy_count:,}")
        if min_entropy > 0:
            print(f"    Entropy threshold   : {min_entropy:.2f}")
        print(f"    Output file         : {resolved_output}")

    except IOError as e:
        print(f"  Error writing output: {e}")
        store.destroy()
        return

    # ── Generate additional output files ──

    # Hashcat rules file
    if generate_rules:
        base, _ = os.path.splitext(resolved_output)
        rules_path = base + ".rule"
        with open(rules_path, 'w', encoding='utf-8') as f:
            f.write(RULE_FILE_HEADER)
            for rule in HASHCAT_RULES:
                f.write(f"{rule}\n")
        print(f"    Rules file          : {rules_path} ({len(HASHCAT_RULES)} rules)")

    # Hashcat mask file
    if generate_masks:
        mask_path = generate_mask_file(store, resolved_output)
        print(f"    Mask file           : {mask_path}")

    # Hash type identification
    if hash_id:
        identified_hashes = identify_hashes_in_store(store)
        if identified_hashes:
            print(f"\n  {Color.bold('Hash Type Identification:')}")
            for hash_name, items in identified_hashes.items():
                hashcat_mode = items[0][1]
                if hashcat_mode > 0:
                    mode_str = f"-m {hashcat_mode}"
                else:
                    mode_str = "-m 0 (MD5) or -m 1000 (NTLM)"
                print(f"    {hash_name:<20s}: {len(items):,} hashes  "
                      f"(hashcat {mode_str})")

    # Username extraction
    if extract_users and user_set:
        base, _ = os.path.splitext(resolved_output)
        users_path = base + "_users.txt"
        with open(users_path, 'w', encoding='utf-8') as f:
            for username in sorted(user_set):
                f.write(f"{username}\n")
        print(f"    Users file          : {users_path} ({len(user_set):,} unique)")

    # JSON export
    if export_json:
        json_count = store.write_json(resolved_output)
        base, _ = os.path.splitext(resolved_output)
        print(f"    JSON export         : {base}.json ({json_count:,} entries)")

    # CSV export
    if export_csv:
        csv_count = store.write_csv(resolved_output)
        base, _ = os.path.splitext(resolved_output)
        print(f"    CSV export          : {base}.csv ({csv_count:,} entries)")

    # Statistics report
    if show_stats:
        stats_report = generate_statistics(store)
        print(stats_report)
        stats_path = os.path.splitext(resolved_output)[0] + "_stats.txt"
        with open(stats_path, 'w', encoding='utf-8') as f:
            f.write(stats_report)
        print(f"  Stats saved to: {stats_path}")

    # Age estimation report
    if age_report:
        age_report_text = generate_age_report(store)
        print(age_report_text)

    # Password reuse report
    if reuse_report:
        reuse_report_text = generate_reuse_report(store)
        print(reuse_report_text)

    # Save incremental state
    if incremental_state:
        for file_path, _ in file_list:
            if file_path in processed_files:
                incremental_state.mark_processed(file_path)
        incremental_state.save()
        print(f"  Incremental state saved.")

    # ── Cleanup ──
    if not interrupted.is_set():
        checkpoint_manager.clear()
    store.destroy()
    print("")


# ──────────────────────────────────────────────────────────────────────────────
# COMMAND-LINE INTERFACE
# ──────────────────────────────────────────────────────────────────────────────

def list_modes() -> str:
    """Return a formatted string describing all available scan modes."""
    lines = ["\nAvailable scan modes:\n"]
    for key, info in SCAN_MODES.items():
        lines.append(f"  {key:<14s} {info['name']}")
        lines.append(f"  {'':<14s} {info['description']}\n")
    lines.append(f"  {'all':<14s} Run All Modes")
    lines.append(f"  {'':<14s} Runs every mode above and merges results.\n")
    return "\n".join(lines)


def main() -> None:
    """Entry point for the command-line interface."""
    mode_names = list(SCAN_MODES.keys()) + ["all"]

    parser = argparse.ArgumentParser(
        description=(
            "PassHarvester v4.0 — Large-scale wordlist builder.\n"
            "Handles 100GB+ directories. 30+ language support.\n"
            "Compatible with aircrack-ng, hashcat, John the Ripper."
        ),
        epilog=(
            "Examples:\n"
            "  python PassHarvester.py ./data -m combo -t 8 -o ~/wordlist.txt\n"
            "  python PassHarvester.py ./breach -m all --stats --rules --masks\n"
            "  python PassHarvester.py ./data --extensions .conf,.env,.yml\n"
            "  python PassHarvester.py ./data --policy 'min_length:8,require_upper'\n"
            "  python PassHarvester.py ./data --track-sources --reuse-report\n"
            "  python PassHarvester.py --compare list1.txt list2.txt\n"
            "  python PassHarvester.py --merge a.txt b.txt -o merged.txt\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Positional argument
    parser.add_argument(
        "start_directory", nargs="?", default=None,
        help="Root directory to scan recursively.",
    )

    # ── Scan Mode group ──
    mode_group = parser.add_argument_group("Scan Mode")
    mode_group.add_argument(
        "-m", "--mode", choices=mode_names, default="general",
        help="Scan mode preset (default: general).",
    )
    mode_group.add_argument(
        "--list-modes", action="store_true",
        help="Show scan mode descriptions and exit.",
    )
    mode_group.add_argument(
        "-p", "--pattern", default=None,
        help="Custom regex pattern — overrides --mode.",
    )
    mode_group.add_argument(
        "--keywords", default=None,
        help="Custom keyword file for credentials/wifi mode (one per line).",
    )

    # ── Output group ──
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output", default="wordlist.txt",
        help="Output file path (default: ./wordlist.txt).",
    )
    output_group.add_argument(
        "-f", "--format",
        choices=["plain", "frequency", "potfile", "john"],
        default="plain",
        help="Output format (default: plain).",
    )
    output_group.add_argument(
        "--rules", action="store_true",
        help="Generate a hashcat .rule file alongside the wordlist.",
    )
    output_group.add_argument(
        "--masks", action="store_true",
        help="Generate a hashcat .hcmask file with password patterns.",
    )
    output_group.add_argument(
        "--stats", action="store_true",
        help="Generate a password statistics report.",
    )
    output_group.add_argument(
        "--export-json", action="store_true",
        help="Export passwords as JSON with metadata.",
    )
    output_group.add_argument(
        "--export-csv", action="store_true",
        help="Export passwords as CSV with metadata.",
    )

    # ── Filtering group ──
    filter_group = parser.add_argument_group("Filtering")
    filter_group.add_argument(
        "--min-entropy", type=float, default=0.0,
        help="Minimum Shannon entropy in bits/char (default: 0 = disabled).",
    )
    filter_group.add_argument(
        "--dedup-case", action="store_true",
        help="Case-insensitive deduplication.",
    )
    filter_group.add_argument(
        "--exclude", default="",
        help="Wordlist to subtract from results (e.g. rockyou.txt).",
    )
    filter_group.add_argument(
        "--policy", default=None,
        help="Password policy filter (e.g. 'min_length:8,require_upper,require_digit').",
    )
    filter_group.add_argument(
        "--extensions", default=None,
        help="Comma-separated file extensions to scan (e.g. '.txt,.conf,.env').",
    )
    filter_group.add_argument(
        "--max-depth", type=int, default=None,
        help="Maximum directory recursion depth.",
    )
    filter_group.add_argument(
        "--newer-than", default=None,
        help="Only scan files modified after this date (YYYY-MM-DD).",
    )

    # ── Performance group ──
    perf_group = parser.add_argument_group("Performance")
    perf_group.add_argument(
        "-t", "--threads", type=int, default=1,
        help="Number of parallel scanning threads (default: 1).",
    )
    perf_group.add_argument(
        "--resume", action="store_true",
        help="Resume from last checkpoint if scan was interrupted.",
    )
    perf_group.add_argument(
        "--incremental", action="store_true",
        help="Only scan files modified since the last run.",
    )

    # ── Analysis group ──
    analysis_group = parser.add_argument_group("Analysis")
    analysis_group.add_argument(
        "--track-sources", action="store_true",
        help="Track which file and line each password came from.",
    )
    analysis_group.add_argument(
        "--extract-users", action="store_true",
        help="Extract usernames/emails from combo lists into a separate file.",
    )
    analysis_group.add_argument(
        "--hash-id", action="store_true",
        help="Identify hash types and display hashcat mode numbers.",
    )
    analysis_group.add_argument(
        "--reuse-report", action="store_true",
        help="Show passwords found across multiple source files.",
    )
    analysis_group.add_argument(
        "--age-report", action="store_true",
        help="Estimate password ages from year patterns.",
    )

    # ── Utilities group ──
    util_group = parser.add_argument_group("Utilities")
    util_group.add_argument(
        "--compare", nargs=2, metavar="FILE",
        help="Compare two wordlists and show overlap statistics.",
    )
    util_group.add_argument(
        "--merge", nargs="+", metavar="FILE",
        help="Merge multiple wordlists into one deduplicated file.",
    )
    util_group.add_argument(
        "--config", default=None,
        help="Load settings from an INI config file.",
    )
    util_group.add_argument(
        "--generate-config", metavar="PATH", default=None,
        help="Generate a sample config file with all options and exit.",
    )
    util_group.add_argument(
        "--no-color", action="store_true",
        help="Disable colored terminal output.",
    )
    util_group.add_argument(
        "-v", "--verbose", action="store_true",
        help="Print per-file progress (disables progress bar).",
    )

    args = parser.parse_args()

    # ── Handle standalone commands ──

    if args.no_color:
        Color.disable()

    if args.generate_config:
        generate_sample_config(args.generate_config)
        sys.exit(0)

    if args.list_modes:
        print(list_modes())
        sys.exit(0)

    if args.compare:
        for filepath in args.compare:
            if not os.path.isfile(filepath):
                print(f"Error: '{filepath}' not found.")
                sys.exit(1)
        compare_wordlists(args.compare[0], args.compare[1])
        sys.exit(0)

    if args.merge:
        for filepath in args.merge:
            if not os.path.isfile(filepath):
                print(f"Error: '{filepath}' not found.")
                sys.exit(1)
        merge_policy = parse_policy(args.policy) if args.policy else None
        merge_wordlists(
            args.merge, args.output, args.dedup_case,
            args.min_entropy, merge_policy
        )
        sys.exit(0)

    # ── Load config file (CLI flags override config values) ──
    if args.config:
        if not os.path.isfile(args.config):
            print(f"Error: Config file '{args.config}' not found.")
            sys.exit(1)
        config_settings = load_config(args.config)
        for key, value in config_settings.items():
            arg_key = key.replace('-', '_')
            if hasattr(args, arg_key):
                current_value = getattr(args, arg_key)
                default_value = parser.get_default(arg_key)
                # Only apply config value if CLI didn't explicitly override
                if current_value == default_value:
                    setattr(args, arg_key, value)

    # ── Validate arguments ──
    if args.start_directory is None:
        parser.error("the following arguments are required: start_directory")

    if not os.path.isdir(args.start_directory):
        print(f"Error: '{args.start_directory}' is not a valid directory.")
        sys.exit(1)

    if args.exclude and not os.path.isfile(args.exclude):
        print(f"Error: Exclusion file '{args.exclude}' not found.")
        sys.exit(1)

    # ── Build regex patterns ──
    password_kw_pattern = load_custom_keywords(args.keywords) if args.keywords else None
    modes = build_scan_modes(password_kw_pattern) if password_kw_pattern else SCAN_MODES

    patterns: List[re.Pattern] = []

    if args.pattern:
        try:
            patterns.append(re.compile(args.pattern, re.MULTILINE | re.UNICODE))
        except re.error as e:
            print(f"Error: Invalid regex pattern: {e}")
            sys.exit(1)
        mode_label = "Custom pattern"

    elif args.mode == "all":
        for info in modes.values():
            patterns.append(re.compile(info["pattern"], re.MULTILINE | re.UNICODE))
        mode_label = "All modes combined"

    else:
        info = modes[args.mode]
        patterns.append(re.compile(info["pattern"], re.MULTILINE | re.UNICODE))
        mode_label = info["name"]

    # ── Parse extension filter ──
    parsed_extensions = None
    if args.extensions:
        parsed_extensions = set(
            ext.strip() if ext.strip().startswith('.') else '.' + ext.strip()
            for ext in args.extensions.split(',')
        )

    # ── Parse newer-than date ──
    newer_than_timestamp = None
    if args.newer_than:
        try:
            newer_than_timestamp = datetime.datetime.strptime(
                args.newer_than, "%Y-%m-%d"
            ).timestamp()
        except ValueError:
            print("Error: --newer-than must be in YYYY-MM-DD format.")
            sys.exit(1)

    # ── Run the scanner ──
    scan_directory(
        start_path=args.start_directory,
        output_path=args.output,
        patterns=patterns,
        mode_name=mode_label,
        verbose=args.verbose,
        num_threads=args.threads,
        min_entropy=args.min_entropy,
        output_format=args.format,
        dedup_case=args.dedup_case,
        show_stats=args.stats,
        generate_rules=args.rules,
        generate_masks=args.masks,
        exclude_path=args.exclude,
        enable_resume=args.resume,
        track_sources=args.track_sources,
        extract_users=args.extract_users,
        hash_id=args.hash_id,
        reuse_report=args.reuse_report,
        age_report=args.age_report,
        export_json=args.export_json,
        export_csv=args.export_csv,
        extensions=parsed_extensions,
        max_depth=args.max_depth,
        newer_than=newer_than_timestamp,
        incremental=args.incremental,
        policy=args.policy,
    )


if __name__ == "__main__":
    main()
