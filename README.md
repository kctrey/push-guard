# push-guard

A safety net on your laptop that checks every `git push` for anything that looks like customer
data, and won't let it leave your machine until **you** confirm it's demo data.

## Why

Customer details end up in code more easily than you'd think: a sample JSON copied from a real
deck, a PDF used as a test fixture, an org ID pasted into a script, a bundle that embeds real
slides. Once that's pushed to GitHub, deleting the file doesn't remove it. It stays in the
history, in pull requests and in GitHub's cache, and only GitHub Support can purge it.
push-guard catches it **before** the push, when fixing it is still easy.

## What it looks for

In every commit you are about to push (lines added, files added or changed, commit messages):

| Kind | Examples |
|---|---|
| Customer / account names | `customerName: "…"`, `"Account Name": "…"`, opportunity, partner, org name fields |
| People | AE, CSM, owner, contact, "who" fields · email addresses · phone numbers |
| Money | `$45,000.00`, `$120k`, `USD 9,900`, TCV / ARR / AAR / price fields |
| IDs | Control Hub org/user IDs (UUIDs), Webex API IDs, subscription IDs (`Sub1234567`), Salesforce IDs |
| Data files | spreadsheets, PDFs, screenshots, decks, docs, large JSON, anything in `data/`, `output/`, `sources/` folders |
| Secrets | tokens and API keys; private keys and `.env` files are **always** blocked |

Optionally it also flags the exact customer names from your own spreadsheets (see *Setup*).

It is pattern-based, so it will flag demo data too. That's on purpose: it can't tell
"Demo Retail Co" from a real customer, so it asks you.

## What happens when you push

**From a terminal:** if something is flagged, it shows each file with the flagged values and asks:

```
[1/2] dashboard/data/slides.json  — 7 item(s), commit 4d3e8230
        line 1  Customer / account name  Acme Demo Corp
                const rows = [{ customerName: "Acme Demo Corp", orgId: "1111…
        line 2  Money amount             $45,000.00
  Is this demo/fake data?  [d] yes, all demo  [r] no, it's real  [o] one by one  [v] view all  [q] quit:
```

- **d**: demo data, so the push continues. Your answer is remembered for that value in that file,
  so you're only asked again when something new or changed shows up.
- **r**: real data, so the push stops and nothing leaves your laptop. Remove it from the commits
  (rewrite them with `git commit --amend` or `git rebase`; deleting it in a new commit isn't
  enough, because the old commit would still be pushed). Then push again.
- **o**: decide item by item.

**From an IDE button, a script or an AI coding assistant** (no terminal to ask in): the push is
blocked and the findings are saved. Run `push-guard --review` yourself in a terminal inside the
repo, then push again. This way an automated tool can't confirm on your behalf.

## Install

Needs `git` and `python3` (macOS or Linux).

```sh
./install.sh                    # check every repo on this machine (recommended)
./install.sh ~/work ~/Projects  # or only repos inside these folders
```

Re-running it updates the code and keeps your local lists. To remove it: `./uninstall.sh`
(add `--purge` to also delete your local lists).

## Setup (optional)

- **Your customer names:** list the folders that hold your customer spreadsheets in
  `~/.config/git/push-guard/term-sources.txt`. push-guard reads the customer / account /
  opportunity name columns and builds `customer-terms.txt`. It refreshes when the spreadsheets
  change and needs `pip install openpyxl`. If openpyxl lives in a virtualenv, put that Python's
  path in `~/.config/git/push-guard/python.txt`.
- **Never-flag list:** `~/.config/git/push-guard/allow.txt`, for values that are never customer
  data (for example a shared test address). Prefer answering **d** when asked; that's scoped to one file.

Everything in `~/.config/git/push-guard/` (`customer-terms.txt`, `reviewed.tsv`, `pending/`) stays on
your machine. Don't commit or share it.

## Useful commands

```sh
push-guard --review                   # confirm a blocked push (run it yourself, in a terminal)
push-guard --scan origin/main..HEAD   # audit a branch without pushing; records nothing
git push --no-verify                  # skips the check entirely; only if you are certain
```

## Limits

- It's a local safety net, not a server-side control. It only protects pushes from machines where
  it's installed, and `--no-verify` skips it.
- It doesn't scan inside binary files (xlsx, pdf, images). It flags the file and you decide.
- Free-text notes can contain names it has no way to recognise. It still catches the IDs, amounts
  and name fields around them.
- Repos that set their own `core.hooksPath` (for example husky) override it.
- Vendored and minified files (`vendor/`, `node_modules/`, `*.min.js`) are flagged as files when
  they look like data, but their lines aren't scanned.

## License

MIT, see [LICENSE](LICENSE).
