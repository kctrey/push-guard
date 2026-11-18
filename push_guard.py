#!/usr/bin/env -S python3 -I
"""
push-guard — local pre-push review that stops anything that looks like customer data from
reaching a git remote until YOU confirm it is demo/fake data.

Installed by install.sh (for every repo, or only chosen folders). Scans every commit being pushed that the remote does not
already have (added lines, new/changed files, commit messages) and flags:
  * customer / account / org / opportunity / partner names (name-like fields + your workbook names)
  * person names in owner/AE/CSM/contact/"who" fields, email addresses, phone numbers
  * dollar / currency amounts and money fields (TCV, ARR, AAR, amount, price, …)
  * org IDs (UUIDs, Webex base64 IDs), subscription IDs (Sub1234567), Salesforce IDs
  * data files (spreadsheets, PDFs, screenshots, docs, JSON/CSV data, data/output folders)
  * tokens and secrets; private keys and .env files are always blocked

Every finding must be confirmed as demo/fake before the push continues:
  * `git push` from your own terminal asks you file by file: demo, real (abort), or one by one.
  * Without a terminal (IDE buttons, scripts, AI assistants) the push is blocked and the findings
    are saved; review them in your terminal with  push-guard --review  and push again.
Confirmed demo items are remembered (as hashes, per repo + file) in reviewed.tsv, so you are only
asked again when something new or changed appears. Audit any range with  push-guard --scan A..B
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

WINDOWS = os.name == "nt"
# Findings quote arbitrary repo content: never crash on a character the console/pipe can't encode.
# Git, mintty and IDEs read hook output as UTF-8 (on Windows Python would otherwise use cp1252).
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

HERE = Path(__file__).resolve().parent
TERMS_FILE = HERE / "customer-terms.txt"
ALLOW_FILE = HERE / "allow.txt"
REVIEWED_FILE = HERE / "reviewed.tsv"
PENDING_DIR = HERE / "pending"
REFRESH = HERE / "refresh_terms.py"
ZERO = "0" * 40
MAX_COMMITS = 5000
SHOW_PER_FILE = 12

DATA_EXT = {
    ".xlsx", ".xlsm", ".xls", ".csv", ".tsv", ".numbers", ".pdf", ".png", ".jpg", ".jpeg", ".gif",
    ".heic", ".webp", ".tiff", ".bmp", ".pptx", ".ppt", ".key", ".docx", ".doc", ".pages", ".eml",
    ".msg", ".har", ".sqlite", ".db", ".zip", ".parquet", ".jsonl", ".ndjson",
}
STRUCTURED_EXT = {".json", ".xml"}
STRUCTURED_MIN_BYTES = 1500
DATA_DIR = re.compile(r"(^|/)(data|output|outputs|sources|staging|exports?|dumps?|backups?)/", re.I)
SECRET_FILE = re.compile(r"(^|/)(\.env(\.[^/]*)?|id_rsa|id_ed25519|[^/]*\.(pem|p12|pfx))$", re.I)
ENV_EXAMPLE = re.compile(r"(^|/)\.env\.(example|sample|template)$", re.I)
# Third-party bundles: still flagged as files if they look like data, but their lines are not scanned.
VENDORED = re.compile(r"(^|/)(vendor|node_modules|third_party)/|\.min\.(js|css)$", re.I)

Q = r"""["'`]"""
NAME_KEYS = (
    r"(?:end[ _-]?)?customer(?:[ _-]?name)?|account(?:[ _-]?name)?|org(?:ani[sz]ation)?[ _-]?name"
    r"|company(?:[ _-]?name)?|client(?:[ _-]?name)?|opportunity(?:[ _-]?name)?|opp[ _-]?name"
    r"|partner(?:[ _-]?name)?|tenant(?:[ _-]?name)?|site[ _-]?name|deal[ _-]?name"
)
PERSON_KEYS = (
    r"who|gathered[ _-]?by|collab[ _-]?ae|ae|csm|owner|contact(?:[ _-]?name)?|rep|sales[ _-]?rep"
    r"|account[ _-]?(?:manager|exec(?:utive)?)|champion|sponsor|author|requester"
)
MONEY_KEYS = (
    r"tcv|acv|arr|aar|mrr|amount|price|revenue|bookings?|deal[ _-]?(?:value|size)|contract[ _-]?value"
    r"|spend|cost|discount|quote|list[ _-]?price|net[ _-]?price"
)


def keyed_string(keys: str) -> re.Pattern:
    """`key: "value"` / `"Key Name" = 'value'` with a non-empty value of up to 120 chars."""
    return re.compile(
        rf"(?<![A-Za-z0-9_.\-])[\"']?(?P<key>{keys})[\"']?\s*[:=]\s*(?P<q>{Q})(?P<val>(?:(?!(?P=q)).){{2,120}}?)(?P=q)",
        re.I,
    )


MONEY = re.compile(
    r"(?<![\w$])[$€£]\s?\d[\d,]*(?:\.\d+)?(?:\s?[kKmMbB]\b)?"
    r"|\b(?:USD|EUR|GBP|CHF)\s?\d[\d,]*(?:\.\d+)?"
    r"|\b\d[\d,]*(?:\.\d+)?\s?(?:USD|EUR|GBP|CHF)\b"
)
PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Org / user ID", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)),
    ("Webex API ID", re.compile(r"Y2lzY29zcGFyazovL[A-Za-z0-9+/=_-]{10,}")),
    ("Subscription ID", re.compile(r"\bSub[\s_-]?\d{5,}\b", re.I)),
    ("Subscription ID", re.compile(
        rf"(?<![A-Za-z0-9_])[\"']?sub(?:scription)?(?:[ _-]?(?:id|no|num|number|ref))?[\"']?\s*[:=]\s*{Q}?[A-Za-z]{{0,4}}\d{{5,}}", re.I)),
    ("Salesforce ID", re.compile(r"\b00[16][A-Za-z0-9]{12}(?:[A-Za-z0-9]{3})?\b")),
    ("Money field", re.compile(
        rf"(?<![A-Za-z0-9_])[\"']?(?:{MONEY_KEYS})[\"']?\s*[:=]\s*{Q}?\s*[$€£]?\s?[1-9][\d,.]+\s?[kKmM]?", re.I)),
    ("Email address", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)*\.[A-Za-z]{2,}\b")),
    ("Phone number", re.compile(r"(?<![\w.+])\+\d{1,3}[\s.-]\(?\d{1,4}\)?(?:[\s.-]\d{2,4}){2,4}(?![\w.])")),
    ("Token / secret", re.compile(
        rf"(?:token|secret|api[_-]?key|password|passwd|bearer|client[_-]?secret)[\"']?\s*[:=]\s*{Q}[A-Za-z0-9._\-/+=]{{16,}}{Q}", re.I)),
    ("Private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
NAME_FIELD = keyed_string(NAME_KEYS)
PERSON_FIELD = keyed_string(PERSON_KEYS)
HARD_BLOCK = {"Private key", "Secret file (.env / key)"}
DEFAULT_ALLOW = [
    "noreply@anthropic.com",
    "/@users\\.noreply\\.github\\.com$/",
    "/@example\\.(com|org|net)$/",
    "git@github.com",
]


# ── helpers ──────────────────────────────────────────────────────────────────────────────────

# Git output is UTF-8 on every platform (don't decode it with the Windows ANSI code page), and
# quotePath=false keeps non-ASCII file names readable instead of "\303\251"-escaped.
GIT = ["git", "-c", "core.quotePath=false"]


def git_ok(*args: str, input: str | None = None) -> tuple[bool, str]:
    p = subprocess.run([*GIT, *args], input=input, capture_output=True, encoding="utf-8", errors="replace")
    return p.returncode == 0, p.stdout


def git(*args: str, input: str | None = None) -> str:
    return git_ok(*args, input=input)[1]


def read_text(p: Path) -> str:
    # utf-8-sig: Notepad and PowerShell may save these files with a byte-order mark.
    return p.read_text(encoding="utf-8-sig", errors="replace")


def repo_id() -> str:
    return git("rev-parse", "--show-toplevel").strip() or os.getcwd()


def load_allow() -> list:
    lines = list(DEFAULT_ALLOW)
    if ALLOW_FILE.exists():
        lines += [l.strip() for l in read_text(ALLOW_FILE).splitlines() if l.strip() and not l.startswith("#")]
    rules = []
    for l in lines:
        if len(l) > 2 and l.startswith("/") and l.endswith("/"):
            try:
                rules.append(re.compile(l[1:-1], re.I))
            except re.error:
                pass
        else:
            rules.append(l.lower())
    return rules


def allowed(text: str, rules: list) -> bool:
    t = text.lower()
    return any((r.search(text) if hasattr(r, "search") else r == t) for r in rules)


def refresh_terms_if_stale() -> None:
    """Rebuild customer-terms.txt when a workbook listed in term-sources.txt is newer (needs openpyxl)."""
    if not REFRESH.exists() or not (HERE / "term-sources.txt").exists():
        return
    cfg = HERE / "python.txt"  # optional: path to a Python that has openpyxl (e.g. a project .venv)
    # Default to the Python running this hook: "python3" is often missing on Windows, or is the
    # Microsoft Store placeholder that only prints "Python was not found".
    py = read_text(cfg).strip().strip('"') if cfg.exists() else ""
    py = py or sys.executable
    try:
        subprocess.run([py, "-I", str(REFRESH), "--if-stale", "--quiet"], capture_output=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        pass


def load_terms() -> list[tuple[str, re.Pattern]]:
    if not TERMS_FILE.exists():
        return []
    out = []
    for line in read_text(TERMS_FILE).splitlines():
        term = line.strip()
        if len(term) < 4 or term.startswith("#"):
            continue
        out.append((term, re.compile(r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])", re.I)))
    return out


def fingerprint(repo: str, path: str, kind: str, value: str) -> str:
    return hashlib.sha256(f"{Path(repo).name}\x00{path}\x00{kind}\x00{value}".encode()).hexdigest()


def load_reviewed() -> set[str]:
    if not REVIEWED_FILE.exists():
        return set()
    return {l.split("\t", 1)[0] for l in read_text(REVIEWED_FILE).splitlines() if l and not l.startswith("#")}


def save_reviewed(items: list[dict]) -> None:
    new = not REVIEWED_FILE.exists()
    with REVIEWED_FILE.open("a", encoding="utf-8", newline="\n") as f:
        if new:
            f.write("# push-guard: items you confirmed as demo/fake data (sha256 \\t date \\t kind \\t file)\n")
        day = time.strftime("%Y-%m-%d")
        for it in items:
            f.write(f"{it['fp']}\t{day}\t{it['kind']}\t{Path(it['repo']).name}/{it['path']}\n")
    REVIEWED_FILE.chmod(0o600)


def excerpt(text: str, start: int, end: int, width: int = 110) -> str:
    text = text.replace("\t", " ")
    pad = max(0, (width - (end - start)) // 2)
    a, b = max(0, start - pad), min(len(text), end + pad)
    s = re.sub(r"\s+", " ", text[a:b]).strip()
    return ("…" if a > 0 else "") + s + ("…" if b < len(text) else "")


# ── scanning ─────────────────────────────────────────────────────────────────────────────────

def remote_known(remote: str) -> list[str]:
    """Commits the remote really has right now (ls-remote), not stale local tracking refs."""
    ok, out = git_ok("ls-remote", remote)
    shas = {l.split()[0] for l in out.splitlines() if l.strip()} if ok else set()
    if not ok:  # offline: fall back to remote-tracking refs
        shas = set(git("for-each-ref", "--format=%(objectname)", f"refs/remotes/{remote}/").split())
    if not shas:
        return []
    # One batched lookup instead of one `git cat-file` per ref: GitHub remotes list every PR ref,
    # and thousands of process starts take minutes on Windows.
    out = git("cat-file", "--batch-check=%(objectname) %(objecttype)", input="\n".join(shas) + "\n")
    return [l.split()[0] for l in out.splitlines() if l.endswith(" commit")]


def check_line(ctx: dict, n: int, text: str, terms, allow, out: list) -> None:
    spans: list[tuple[str, int, int]] = []

    def add(kind: str, value: str, s: int, e: int) -> None:
        group = kind.split()[0]  # "Money field"/"Money amount" etc. overlap → report once
        if allowed(value, allow) or any(g == group and s < b and a < e for g, a, b in spans):
            return
        spans.append((group, s, e))
        out.append({**ctx, "line": n, "kind": kind, "value": value[:200], "context": excerpt(text, s, e, 80)})

    for kind, rx in PATTERNS:
        for m in rx.finditer(text):
            add(kind, m.group(0), m.start(), m.end())
    for m in MONEY.finditer(text):
        v = m.group(0)
        if sum(c.isdigit() for c in v) >= 2 or re.search(r"[kKmMbB]$|USD|EUR|GBP|CHF", v):
            add("Money amount", v, m.start(), m.end())
    for kind, rx in (("Customer / account name", NAME_FIELD), ("Person name", PERSON_FIELD)):
        for m in rx.finditer(text):
            v = m.group("val").strip()
            same_as_key = v.lower().replace("_", " ") == m.group("key").lower().replace("_", " ")
            if re.search(r"[A-Za-z]", v) and not same_as_key and not v.startswith(("${", "{{", "<%")):
                add(kind, v, m.start(), m.end())
    for term, rx in terms:
        for m in rx.finditer(text):
            add("Customer name (workbook)", m.group(0), m.start(), m.end())


def scan_commit(sha: str, repo: str, terms, allow, out: list) -> None:
    short = sha[:8]
    msg = git("log", "-1", "--format=%B", sha)
    for i, line in enumerate(msg.splitlines(), 1):
        check_line({"repo": repo, "commit": short, "path": "(commit message)"}, i, line, terms, allow, out)

    # --raw gives the new blob id directly (":100644 100644 <old> <new> M\tpath"), so no extra
    # `git rev-parse` per file.
    for row in git("diff-tree", "--no-commit-id", "-r", "--root", "-m", "--first-parent", "--raw", "--no-abbrev", sha).splitlines():
        meta, _, names = row.partition("\t")
        meta = meta.split()
        if not row.startswith(":") or len(meta) < 5 or meta[4][:1] not in ("A", "M", "R", "C"):
            continue
        status, blob, path = meta[4][:1], meta[3], names.split("\t")[-1]
        if allowed(path, allow) or ENV_EXAMPLE.search(path):
            continue
        ext = os.path.splitext(path)[1].lower()
        kind = None
        if SECRET_FILE.search(path):
            kind = "Secret file (.env / key)"
        elif ext in DATA_EXT:
            kind = "Data / document file"
        elif DATA_DIR.search(path):
            kind = "File in a data folder"
        elif ext in STRUCTURED_EXT:
            size = git("cat-file", "-s", blob).strip()
            if size.isdigit() and int(size) >= STRUCTURED_MIN_BYTES:
                kind = "Structured data file"
        if kind:
            out.append({"repo": repo, "commit": short, "path": path, "line": 0, "kind": kind,
                        "value": f"blob {blob}", "context": f"whole file ({status})"})

    diff = git("diff-tree", "--no-commit-id", "-r", "--root", "-m", "--first-parent", "-p", "-U0",
               "--no-color", "--no-ext-diff", "--text", sha)
    path, line_no = "?", 0
    # split("\n"), not splitlines(): a stray \r, \f or \x1c inside a line must not shift line numbers.
    for line in diff.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        if line.startswith("diff --git "):
            path = line.split(" b/", 1)[-1]
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            line_no = int(m.group(1)) if m else 0
        elif line.startswith("+") and not line.startswith("+++"):
            if not allowed(path, allow) and not VENDORED.search(path):
                check_line({"repo": repo, "commit": short, "path": path}, line_no, line[1:], terms, allow, out)
            line_no += 1


def collect(commits: list[str]) -> list[dict]:
    refresh_terms_if_stale()
    terms, allow, repo = load_terms(), load_allow(), repo_id()
    raw: list[dict] = []
    for sha in commits:
        scan_commit(sha, repo, terms, allow, raw)
    uniq: dict[str, dict] = {}
    for f in raw:
        f["fp"] = fingerprint(repo, f["path"], f["kind"], f["value"])
        uniq.setdefault(f["fp"], f)
    return list(uniq.values())


# ── review ───────────────────────────────────────────────────────────────────────────────────

def _win_handle(f):
    import msvcrt
    try:
        return msvcrt.get_osfhandle(f.fileno())
    except (OSError, ValueError, AttributeError):
        return None


def _win_is_console(f) -> bool:
    """True only for a real console handle. Not os.isatty(): that is also True for NUL."""
    import ctypes
    from ctypes import wintypes
    h = _win_handle(f)
    mode = wintypes.DWORD()
    return h is not None and bool(ctypes.windll.kernel32.GetConsoleMode(wintypes.HANDLE(h), ctypes.byref(mode)))


def _win_is_mintty(f) -> bool:
    """True when f is the input pipe of a Git Bash (mintty) window, which isn't a Windows console."""
    import ctypes
    from ctypes import wintypes
    h = _win_handle(f)
    if h is None:
        return False
    buf = ctypes.create_string_buffer(4 + 2 * 1024)
    if not ctypes.windll.kernel32.GetFileInformationByHandleEx(wintypes.HANDLE(h), 2, buf, ctypes.sizeof(buf)):
        return False  # 2 = FileNameInfo
    n = int.from_bytes(buf.raw[:4], "little")
    name = buf.raw[4:4 + n].decode("utf-16-le", "replace")
    # e.g. \msys-1888ae32e00d56aa-pty0-from-master-nat (newer runtimes add "-nat" for native programs)
    return re.search(r"\\(msys|cygwin)-[0-9a-f]+-pty\d+-from-master(-nat)?$", name) is not None


def _win_enable_ansi(f) -> None:
    import ctypes
    from ctypes import wintypes
    h, mode = _win_handle(f), wintypes.DWORD()
    k = ctypes.windll.kernel32
    if h is not None and k.GetConsoleMode(wintypes.HANDLE(h), ctypes.byref(mode)):
        k.SetConsoleMode(wintypes.HANDLE(h), mode.value | 0x0004)  # ENABLE_VIRTUAL_TERMINAL_PROCESSING


def open_tty(allow_stdin: bool = False):
    """The user's terminal for the demo/real questions, or (None, None) when nobody can answer."""
    if not WINDOWS:
        try:
            return open("/dev/tty"), open("/dev/tty", "w")
        except OSError:
            return None, None
    # Windows has no /dev/tty. CONIN$ opens even for IDEs, scripts and AI assistants (they get a
    # hidden console), so only use it when git's stderr really is a console: a terminal window.
    if _win_is_console(sys.stderr):
        try:
            tin = open("CONIN$", encoding="utf-8")
            tout = open("CONOUT$", "w", encoding="utf-8")
        except OSError:
            return None, None
        _win_enable_ansi(tout)
        return tin, tout
    # Git Bash's own window (mintty) is a pipe, not a console. During a push stdin carries git's
    # ref list so we can't ask there, but `push-guard --review` typed in that window can.
    if allow_stdin and _win_is_mintty(sys.stdin):
        return sys.stdin, sys.stdout
    return None, None


def fmt(f: dict) -> str:
    loc = f"line {f['line']}" if f["line"] else "file"
    if not f["line"]:
        return f"    {loc:>10}  {f['kind']:<24} {f['context']}"
    val = re.sub(r"\s+", " ", f["value"])[:40]
    return f"    {loc:>10}  {f['kind']:<24} \033[1m{val}\033[0m\n{'':16}\033[2m{f['context'][:100]}\033[0m"


def ask(tin, tout, prompt: str, choices: str) -> str:
    while True:
        tout.write(prompt)
        tout.flush()
        a = tin.readline()
        if not a:
            return "q"
        a = a.strip().lower()[:1]
        if a and a in choices:
            return a


def review(findings: list[dict], tin, tout) -> int:
    """Interactive demo/real confirmation. 0 = all confirmed demo; 1 = abort."""
    w = tout.write
    groups: dict[str, list[dict]] = {}
    for f in findings:
        groups.setdefault(f["path"], []).append(f)
    w(f"\n\033[1;33mpush-guard: {len(findings)} item(s) in {len(groups)} file(s) look like customer data.\033[0m\n"
      "Confirm each file is demo/fake data before it leaves this machine.\n")

    hard = [f for f in findings if f["kind"] in HARD_BLOCK]
    if hard:
        w("\n\033[1;31mAlways blocked (secrets):\033[0m\n" + "\n".join(f"  {f['path']}: {f['kind']}" for f in hard) + "\n"
          "Remove these from the commits, then push again.\n")
        return 1

    demo: list[dict] = []
    real: list[dict] = []
    for gi, (path, items) in enumerate(groups.items(), 1):
        commits = ", ".join(dict.fromkeys(i["commit"] for i in items))
        w(f"\n\033[1m[{gi}/{len(groups)}] {path}\033[0m  — {len(items)} item(s), commit {commits}\n")
        for f in items[:SHOW_PER_FILE]:
            w(fmt(f) + "\n")
        more = len(items) - SHOW_PER_FILE
        if more > 0:
            w(f"    … {more} more (press v to list them)\n")
        while True:
            a = ask(tin, tout, "  Is this demo/fake data?  [d] yes, all demo  [r] no, it's real  "
                    "[o] one by one  [v] view all  [q] quit: ", "drovq")
            if a == "v":
                for f in items:
                    w(fmt(f) + "\n")
                continue
            break
        if a == "q":
            w("\nReview stopped — nothing pushed.\n")
            return 1
        if a == "d":
            demo += items
        elif a == "r":
            real += items
        else:
            for f in items:
                w(fmt(f) + "\n")
                b = ask(tin, tout, "      [d] demo  [r] real  [q] quit: ", "drq")
                if b == "q":
                    w("\nReview stopped — nothing pushed.\n")
                    return 1
                (demo if b == "d" else real).append(f)

    if demo:
        save_reviewed(demo)
    if real:
        w(f"\n\033[1;31mpush-guard: push blocked — {len(real)} item(s) marked as REAL customer data:\033[0m\n")
        for path in dict.fromkeys(f["path"] for f in real):
            cs = ", ".join(dict.fromkeys(f["commit"] for f in real if f["path"] == path))
            w(f"  • {path}  (commit {cs})\n")
        w("Every pushed commit is checked, so deleting it in a new commit is not enough: rewrite the\n"
          "commits that add it (git rebase / git commit --amend), then push again.\n")
        return 1
    w(f"\npush-guard: {len(demo)} item(s) confirmed as demo data — continuing.\n")
    return 0


def pending_file() -> Path:
    return PENDING_DIR / (hashlib.sha256(repo_id().encode()).hexdigest()[:16] + ".json")


def save_pending(findings: list[dict], refs: list[str]) -> Path:
    PENDING_DIR.mkdir(mode=0o700, exist_ok=True)
    p = pending_file()
    p.write_text(json.dumps({"repo": repo_id(), "refs": refs, "time": time.strftime("%Y-%m-%d %H:%M"),
                             "findings": findings}, indent=1), encoding="utf-8")
    p.chmod(0o600)
    return p


def print_blocked(findings: list[dict]) -> None:
    e = sys.stderr.write
    files = list(dict.fromkeys(f["path"] for f in findings))
    e(f"\n\033[1;31mpush-guard: push blocked — {len(findings)} item(s) in {len(files)} file(s) need your review\033[0m\n")
    for path in files[:25]:
        items = [f for f in findings if f["path"] == path]
        kinds = ", ".join(dict.fromkeys(f["kind"] for f in items))
        e(f"  • {path}: {len(items)} × {kinds}\n")
    if len(files) > 25:
        e(f"  … and {len(files) - 25} more files\n")
    e("\nNo terminal to ask you in, so nothing was pushed. To confirm demo vs real data, run in your\n"
      f"own terminal (inside this repo):\n\n    {review_command()}\n\n"
      "then push again. Or run `git push` yourself from a terminal to review inline.\n")
    if WINDOWS:
        e("(In the Git Bash window, a push can't ask you inline; use the command above there.)\n")


def review_command() -> str:
    if shutil.which("push-guard"):
        return "push-guard --review"
    return f'"{sys.executable}" -I "{HERE / "push_guard.py"}" --review'


# ── entry points ─────────────────────────────────────────────────────────────────────────────

def hook(argv: list[str]) -> int:
    remote = argv[1] if len(argv) > 1 else "origin"
    stdin_data = sys.stdin.read()
    known = None
    commits: list[str] = []
    refs: list[str] = []
    for line in stdin_data.splitlines():
        parts = line.split()
        if len(parts) != 4 or parts[1] == ZERO:
            continue  # malformed or branch deletion
        refs.append(parts[2])
        if known is None:
            known = remote_known(remote)
        # Revisions go through stdin: thousands of remote refs on the command line exceed the
        # Windows limit of 32K characters ("WinError 206: The filename or extension is too long").
        cs = git("rev-list", f"--max-count={MAX_COMMITS}", "--stdin",
                 input="\n".join([parts[1], *(f"^{k}" for k in known)]) + "\n").split()
        commits += [c for c in cs if c not in commits]

    reviewed = load_reviewed()
    findings = collect(commits)
    open_items = [f for f in findings if f["fp"] not in reviewed or f["kind"] in HARD_BLOCK]
    skipped = len(findings) - len(open_items)

    if open_items:
        tin, tout = open_tty()
        if tin is None:
            save_pending(open_items, refs)
            print_blocked(open_items)
            return 1
        rc = review(open_items, tin, tout)
        if rc:
            return rc
        pending_file().unlink(missing_ok=True)

    note = f", {skipped} already confirmed as demo" if skipped else ""
    sys.stderr.write(f"push-guard: {len(commits)} commit(s) checked — nothing unreviewed{note}.\n")
    own = Path(git("rev-parse", "--git-common-dir").strip() or ".git") / "hooks" / "pre-push"
    if own.is_file() and os.access(own, os.X_OK) and own.resolve().parent != HERE / "hooks":
        return subprocess.run([*hook_command(own), *argv[1:]], input=stdin_data, text=True).returncode
    return 0


def hook_command(path: Path) -> list[str]:
    """How to run a repo's own hook. Windows can't execute a `#!` script directly ([WinError 193]),
    so hand it to Git's sh, which honours the shebang like Git itself does."""
    if not WINDOWS or path.suffix.lower() in (".exe", ".bat", ".cmd"):
        return [str(path)]
    sh = shutil.which("sh")
    if not sh:  # Git for Windows: <git>/mingw64/libexec/git-core -> <git>/usr/bin/sh.exe
        cand = Path(git("--exec-path").strip()).parents[2] / "usr" / "bin" / "sh.exe"
        sh = str(cand) if cand.exists() else None
    return [sh, "-c", '"$0" "$@"', path.as_posix()] if sh else [str(path)]


def cmd_review() -> int:
    p = pending_file()
    if not p.exists():
        print("push-guard: nothing waiting for review in this repo.")
        return 0
    data = json.loads(read_text(p))
    reviewed = load_reviewed()
    items = [f for f in data["findings"] if f["fp"] not in reviewed]
    if not items:
        p.unlink()
        print("push-guard: everything already reviewed — push again.")
        return 0
    tin, tout = open_tty(allow_stdin=True)
    if tin is None:
        print("push-guard --review must be run by you in a real terminal (it asks you to confirm).", file=sys.stderr)
        return 1
    tout.write(f"Pending from push of {', '.join(data['refs'])} at {data['time']}\n")
    rc = review(items, tin, tout)
    if rc == 0:
        p.unlink(missing_ok=True)
        tout.write("Now run your git push again.\n")
    return rc


def cmd_scan(args: list[str]) -> int:
    """Audit only: list findings for a revision range, never records approvals."""
    commits = git("rev-list", f"--max-count={MAX_COMMITS}", *(args or ["HEAD"])).split()
    findings = collect(commits)
    reviewed = load_reviewed()
    for f in findings:
        mark = "demo-ok" if f["fp"] in reviewed else "REVIEW "
        print(f"{mark} {f['commit']} {f['path']}:{f['line']}  {f['kind']:<26} {f['context'][:100]}")
    print(f"\n{len(commits)} commit(s), {len(findings)} finding(s), "
          f"{sum(f['fp'] not in reviewed for f in findings)} unreviewed.")
    return 1 if any(f["fp"] not in reviewed for f in findings) else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["--review"]:
        sys.exit(cmd_review())
    if a[:1] == ["--scan"]:
        sys.exit(cmd_scan(a[1:]))
    sys.exit(hook(sys.argv))
