"""Plain-language explanations for EVTX files that could not be opened.

The parser reports the operating system's own error text, e.g.
``Access is denied. (os error 5)``.  That is exact, and is kept verbatim on
each file's line, but it does not tell an examiner WHY or WHAT TO DO.  The
usual causes are few and fixable:

* the file is protected by its file permissions -- Windows' own event-log
  folder, or evidence copied out of a mounted image with the source machine's
  ACLs still attached;
* another program has the file open and locked;
* the file is no longer at that path.

``explain_open_errors()`` turns the error lines of one parse into a short
paragraph per cause that occurred, for the bottom of the warning dialog, so
a parse with forty locked files gets one explanation, not forty.
"""

from __future__ import annotations

import re

# (cause, pattern over the error text, explanation)
_CAUSES: list[tuple[str, re.Pattern, str]] = [
    (
        "access",
        re.compile(r"os error 5\b|access is denied|permission denied|\[errno 13\]", re.I),
        "“Access is denied”: Windows blocked reading the file because of its "
        "file permissions (common for Windows’ own log folder, or for logs copied "
        "out of a mounted image with the original machine’s permissions). "
        "Copy the file to a normal folder, such as your case folder, and add the "
        "copy — or run EventHawk as Administrator.",
    ),
    (
        "in_use",
        re.compile(r"os error 32\b|being used by another process|sharing violation", re.I),
        "“In use”: another program has the file open and locked. Close that "
        "program, or copy the file and add the copy.",
    ),
    (
        "missing",
        re.compile(r"os error [23]\b|cannot find the (file|path)|no such file", re.I),
        "“Not found”: the file is no longer at that path — it was moved, "
        "renamed, or is on a drive that is no longer connected. Add it again "
        "from where it is now.",
    ),
]


def open_error_causes(text: str) -> list[str]:
    """The cause keys ("access", "in_use", "missing") found in *text*."""
    return [key for key, pat, _ in _CAUSES if pat.search(text or "")]


def explain_open_errors(lines) -> str:
    """One paragraph per open-error cause present in *lines*, or ``""``.

    Each paragraph is prefixed with how many of the lines it covers, so the
    examiner can tell "one stray file" from "the whole folder" at a glance.
    """
    lines = [str(x) for x in (lines or [])]
    out = []
    for key, pat, text in _CAUSES:
        n = sum(1 for line in lines if pat.search(line))
        if n:
            out.append(f"{n} file(s) — {text}")
    return "\n\n".join(out)
