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

``explain_open_errors()`` turns the error texts of one parse into a short
paragraph per cause that occurred, for the bottom of the warning dialog, so
a parse with forty locked files gets one explanation, not forty.  The advice
never involves changing the original file: a locked or protected log is
copied by a tool that can read it, and the copy's hash is checked.
"""

from __future__ import annotations

import os
import re

# (cause, words in the error text, Windows error codes, explanation)
# The codes are matched as "(os error N)" (the parser's form) or "[WinError N]"
# (Python's), and only on Windows: elsewhere the same numbers mean other
# things (os error 5 is EIO on Linux).  The words also cover non-English
# Windows through the codes, and POSIX text such as "Permission denied".
_CAUSES: list[tuple[str, re.Pattern, tuple[int, ...], str]] = [
    (
        "access",
        re.compile(r"access is denied|permission denied|\[errno 13\]", re.I),
        (5,),
        "“Access is denied”: Windows blocked reading the file because of its "
        "file permissions (common for Windows’ own log folder, or for logs copied "
        "out of a mounted image with the original machine’s permissions). "
        "Make a working copy with an account that can read it — an elevated "
        "(Administrator) copy, or robocopy /B — check the copy’s hash against the "
        "original, and add the copy; or run EventHawk as Administrator, which only "
        "reads the file. Do not change the original’s permissions or owner.",
    ),
    (
        "in_use",
        re.compile(r"being used by another process|sharing violation|"
                   r"another process has locked", re.I),
        (32, 33),
        "“In use”: another program has the file open and locked (for live logs, "
        "Windows’ own Event Log service). Close that program, or take a copy with "
        "a tool that can read locked files — a Volume Shadow Copy or your forensic "
        "imager — check its hash, and add the copy.",
    ),
    (
        "missing",
        re.compile(r"cannot find the (?:file|path)|no such file|"
                   r"network path was not found|network name cannot be found|"
                   r"device is not ready", re.I),
        (2, 3, 21, 53, 67),
        "“Not found”: the file is no longer at that path — it was moved, "
        "renamed, or is on a drive or network share that is no longer "
        "connected. Add it again from where it is now.",
    ),
    (
        "not_evtx",
        re.compile(r"failed to read EVTX file header|failed to fill whole buffer|"
                   r"invalid EVTX file header|InvalidEvtxFileHeaderMagic", re.I),
        (),
        "“Not an event log”: the file is empty, cut short, or is not an EVTX "
        "file at all (for example another kind of file with the .evtx ending, or "
        "a copy that stopped part-way). Check its size and where it came from; "
        "if it should be a log, take a fresh copy and check the copy’s hash.",
    ),
]

_CODE_RE = re.compile(r"\(os error (\d+)\)|\[WinError (\d+)\]", re.I)
_ENGINE_LINE_RE = re.compile(r"^Parse error [^:]*: (.*)$", re.S)


def engine_error_text(line: str) -> str:
    """The error part of a Normal-mode engine line, or ``""``.

    The engine reports ``Parse error <file name>: <error>``; a Windows file
    name cannot contain ``:``, so the error is everything after the first
    ``": "``.  Reading only that part means a file NAME ("no such file.evtx")
    never triggers an explanation.  Other lines (``Timeout (…): <file>``,
    ``Worker exception for <file>: …`` -- which can come from a temp or output
    write, not the evidence file) are not explained.
    """
    m = _ENGINE_LINE_RE.match(str(line or ""))
    return m.group(1) if m else ""


def open_error_causes(text: str, windows: bool | None = None) -> list[str]:
    """The cause keys ("access", "in_use", "missing", "not_evtx") found in *text*."""
    if windows is None:
        windows = os.name == "nt"
    text = str(text or "")
    codes = {int(a or b) for a, b in _CODE_RE.findall(text)} if windows else set()
    return [key for key, words, nums, _ in _CAUSES
            if words.search(text) or codes.intersection(nums)]


def explain_open_errors(texts, windows: bool | None = None) -> str:
    """One paragraph per open-error cause present in *texts*, or ``""``.

    *texts* are error texts (see ``engine_error_text`` for Normal mode's
    lines).  Each is counted once, under its first cause, and each paragraph
    is prefixed with how many files it covers, so the examiner can tell "one
    stray file" from "the whole folder" at a glance.
    """
    counts: dict[str, int] = {}
    for t in texts or []:
        causes = open_error_causes(t, windows)
        if causes:
            counts[causes[0]] = counts.get(causes[0], 0) + 1
    return "\n\n".join(f"{counts[key]} file(s) — {text}"
                       for key, _w, _n, text in _CAUSES if counts.get(key))
