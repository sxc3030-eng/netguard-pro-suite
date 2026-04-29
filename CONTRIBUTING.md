# Contributing to NetGuard Pro Suite

Thanks for considering a contribution. This document covers everything
needed to land a patch — code of conduct, dev setup, branch naming,
PR checklist, and the licence implications of contributing.

---

## Code of conduct

This project follows the
[Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
Be respectful, assume good faith, and prefer technical discussion over
personal positions. Maintainers may remove comments, commits, or pull
requests that violate the covenant.

To report a code-of-conduct issue, contact the maintainer privately
through the email on the
[GitHub profile](https://github.com/sxc3030-eng).

---

## Dev setup

```bash
git clone https://github.com/sxc3030-eng/netguard-pro-suite.git
cd netguard-pro-suite
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux / macOS
source .venv/bin/activate

pip install -r requirements.txt

# Run NetGuard backend (needs Npcap on Windows, root on Linux):
python netguard.py --no-block

# Run the Argus browser (PyQt6, needs the QtWebEngine wheel):
python argus_pyqt.py
```

The test suite lives under `tests/`:

```bash
pytest tests/ -q
```

---

## Branch naming

Use one of:

- `feature/<short-name>`  — new user-visible capability
- `fix/<short-name>`      — bug fix, no behaviour change otherwise
- `docs/<short-name>`     — documentation only
- `chore/<short-name>`    — refactor, dependency bump, build script
- `security/<short-name>` — security fix; coordinate with maintainers
                            via private advisory before opening the PR

Examples: `feature/argus-coffre-real`, `fix/netguard-syn-flood-window`,
`docs/authenticode-guide`.

---

## Pull request checklist

Before opening a PR, verify each item:

- [ ] All existing tests pass (`pytest tests/ -q`).
- [ ] New behaviour is covered by at least one test.
- [ ] No real secrets in the diff (API keys, passwords, private hosts).
      Run `git diff main..HEAD` and skim for `sk-`, `aws_`, etc.
- [ ] Every newly added Python or Markdown file carries the GPL v3
      header (see existing files for the template).
- [ ] Public functions and class signatures have type hints
      (PEP 484).
- [ ] Lint and security checks (`pip-audit`, `bandit`) pass locally
      if you ran them — CI runs them anyway.
- [ ] If you added a user-visible string, it is in English (the
      project ships an i18n layer for FR / ES translation later).
- [ ] If your change touches the threat model, `SECURITY.md` is
      updated to match what is and isn't protected.

---

## Sign-off (DCO)

Every commit needs a `Signed-off-by:` line attesting that you wrote
the change yourself or have the right to submit it under the project
licence. See the [Developer Certificate of Origin](https://developercertificate.org/)
for the full text.

In practice, append `-s` to your commits:

```bash
git commit -s -m "fix(netguard): correct SYN flood threshold"
```

`git` will append a line like:

```
Signed-off-by: Jane Doe <jane@example.com>
```

PRs without sign-off cannot be merged.

---

## Licence agreement

By contributing, you agree that your contribution is released under the
[GNU General Public License v3.0](LICENSE), the same licence as the
rest of the suite. There is no separate CLA. The DCO sign-off above
covers the legal attestation.

If you contribute code derived from another GPL-compatible project,
clearly attribute the upstream source and licence in the commit
message and, where appropriate, in a comment at the top of the file.

---

> Copyright © 2026 NetGuard Pro Suite contributors. This document is
> part of the suite and is itself licensed under GPL v3.
