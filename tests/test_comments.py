"""The shipped source and header describe the code as it is.

A comment or docstring that narrates what the code "used to" do is true at one
version and wrong for every reader after it; the changelog is where a change is
recorded. This scans every ``.py`` under ``src/pktcap`` and the shipped
``AGENTS.md`` for that wording, and for references a reader of the public
repository cannot open, and fails naming the file and line.

A phrase that is a fact and not history goes in ``_ALLOWED`` with a reason.
"""

import re
import sys
from pathlib import Path

_PACKAGE = Path(__file__).resolve().parent.parent / "src" / "pktcap"

_HISTORY = re.compile(
    r"\bused to\b|\bno longer\b|\bpreviously\b|\bthe old\b|\bhas always\b"
    r"|\bas before\b|\bwas a (?:real )?bug\b|\bturned out\b|\bearlier version\b"
    r"|\bbefore the fix\b|\bnow\b",
    re.IGNORECASE,
)

#: What only private working notes could explain: a notes path, a numbered
#: step of a plan, a decision id. Assembled from pieces so that this file does
#: not contain the wording it looks for.
_PRIVATE = re.compile(
    r"\." + "agents" + r"\b|\b" + "Phase" + r" [0-9]|\b" + "D" + r"[0-9]{2}\b"
)

#: ``(substring of the line, why the phrase is a fact and not history)``.
_ALLOWED = ()


def _sources():
    return sorted(_PACKAGE.rglob("*.py")) + sorted(_PACKAGE.rglob("AGENTS.md"))


def _allowed(line):
    return any(fragment in line for fragment, _reason in _ALLOWED)


def _offences():
    found = []
    for path in _sources():
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), 1):
            if (_HISTORY.search(line) or _PRIVATE.search(line)) and not _allowed(line):
                found.append(
                    "%s:%d: %s"
                    % (path.relative_to(_PACKAGE).as_posix(), number, line.strip())
                )
    return found


def test_the_package_comments_narrate_no_history():
    found = _offences()
    assert not found, (
        "state the property, or add a fact-not-history phrase to _ALLOWED:\n"
        + "\n".join(found)
    )


def test_the_shipped_header_is_scanned():
    assert "AGENTS.md" in {p.relative_to(_PACKAGE).as_posix() for p in _sources()}


def test_a_planted_phrase_is_caught(tmp_path, monkeypatch):
    (tmp_path / "AGENTS.md").write_text(
        "# header\n\nThis used to raise ValueError.\n", encoding="utf-8"
    )
    planted = "see " + "Phase" + " 3 of the plan"
    (tmp_path / "_x.py").write_text("# %s\n" % planted, encoding="utf-8")
    monkeypatch.setattr(sys.modules[__name__], "_PACKAGE", tmp_path)
    found = _offences()
    assert any(line.startswith("AGENTS.md:3:") for line in found)
    assert any(line.startswith("_x.py:1:") for line in found)


def test_every_allowed_phrase_is_still_in_the_source():
    # An entry whose phrase has gone is an exemption nothing needs.
    texts = [path.read_text(encoding="utf-8") for path in _sources()]
    stale = [
        fragment
        for fragment, _reason in _ALLOWED
        if not any(fragment in text for text in texts)
    ]
    assert stale == []
