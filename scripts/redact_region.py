#!/usr/bin/env python3
"""Replace a delimited region of a file with a stub.

Usage: redact_region.py <target_file> <stub_file> <start_marker> <end_marker>

Finds the first <start_marker>, then the next <end_marker> after it, and
replaces everything from start (inclusive) up to end (exclusive) with the
contents of <stub_file>. The end marker line and everything after it are kept.

Fails loudly (exit 1) if either marker is missing — that means upstream moved
the section, and we must NOT silently ship un-redacted code.
"""
import sys

def main():
    if len(sys.argv) != 5:
        sys.exit(__doc__)
    target, stub, start, end = sys.argv[1:5]
    text = open(target).read()
    i = text.find(start)
    if i == -1:
        sys.exit(f"redact_region: start marker not found in {target!r}: {start!r}")
    j = text.find(end, i + len(start))
    if j == -1:
        sys.exit(f"redact_region: end marker not found in {target!r}: {end!r}")
    replacement = open(stub).read()
    open(target, "w").write(text[:i] + replacement + text[j:])
    print(f"redacted {target}: replaced {j - i} bytes between markers")

if __name__ == "__main__":
    main()
