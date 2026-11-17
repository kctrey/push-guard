#!/usr/bin/env python3
"""
Build push-guard's local customer-name list (customer-terms.txt) from your own spreadsheets.
List the folders that hold your customer workbooks in ~/.config/git/push-guard/term-sources.txt
(one per line, ~ allowed). The generated list stays on your machine and is never committed.

    python3 ~/.config/git/push-guard/refresh_terms.py      # needs openpyxl (pip install openpyxl)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "customer-terms.txt"
SOURCES_FILE = HERE / "term-sources.txt"


def sources() -> list[Path]:
    if not SOURCES_FILE.exists():
        return []
    return [Path(l.strip()).expanduser() for l in SOURCES_FILE.read_text().splitlines()
            if l.strip() and not l.strip().startswith("#")]
NAME_COLUMNS = {"account name", "opportunity name", "customer name", "end customer", "customer"}
DICT = Path("/usr/share/dict/words")
PLACEHOLDERS = {"customername", "oppname", "accountname", "customer", "opportunity", "partnername"}


def workbooks() -> list[Path]:
    files = []
    for d in sources():
        if d.is_dir():
            files += [p for p in d.rglob("*") if p.suffix.lower() in (".xlsx", ".xlsm") and not p.name.startswith("~$")]
    return files


def main() -> None:
    quiet = "--quiet" in sys.argv
    books = workbooks()
    if "--if-stale" in sys.argv and OUT.exists():
        newest = max((p.stat().st_mtime for p in books), default=0)
        if newest <= OUT.stat().st_mtime:
            return
    try:
        import openpyxl
    except ImportError:
        sys.exit("openpyxl not available — pip install openpyxl, or put the path of a Python that has it in python.txt")

    common = {w.strip().lower() for w in DICT.read_text().splitlines()} if DICT.exists() else set()
    terms: set[str] = set()
    for path in books:
        try:
            wb = openpyxl.load_workbook(path, read_only=True, data_only=True)
        except Exception:
            continue
        for ws in wb.worksheets:
            rows = ws.iter_rows(values_only=True)
            header = next(rows, None) or []
            idx = [i for i, h in enumerate(header) if str(h or "").strip().lower() in NAME_COLUMNS]
            for row in rows:
                for i in idx:
                    v = str(row[i] or "").strip() if i < len(row) else ""
                    for part in [v, v.split("#")[0]]:
                        part = re.sub(r"\s+", " ", part).strip(" -#")
                        if len(part) < 4 or part.lower().replace(" ", "") in PLACEHOLDERS:
                            continue
                        if " " not in part and part.lower() in common:
                            continue  # a plain English word (e.g. "REVIEW") would cause false alarms
                        terms.add(part)
    OUT.write_text(
        "# push-guard customer names — generated from your Check Back workbooks; local only.\n"
        + "\n".join(sorted(terms, key=str.lower))
        + "\n"
    )
    OUT.chmod(0o600)
    if not quiet:
        print(f"Wrote {len(terms)} customer names from {len(books)} workbook(s) to {OUT}")


if __name__ == "__main__":
    main()
