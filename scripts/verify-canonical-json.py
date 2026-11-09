#!/usr/bin/env python3
"""Independent RFC 8785 check for packages/audit-verify/src/canonical-json.vectors.json.

This file does not import the TypeScript implementation. It re-derives the
canonical string and compares it to the committed vector.
"""

from __future__ import annotations

import json
import math
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
VECTORS = ROOT / "packages" / "audit-verify" / "src" / "canonical-json.vectors.json"
DANGEROUS = {"__proto__", "constructor", "prototype"}


def es_number(value: float) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("number required")
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        raise ValueError("non-finite")
    if value == 0:
        return "0"
    text = json.dumps(value)
    if "e" not in text and "E" not in text:
        return text
    mantissa, exponent = text.lower().split("e", 1)
    sign = ""
    if exponent.startswith("+"):
        exponent = exponent[1:]
    elif exponent.startswith("-"):
        sign = "-"
        exponent = exponent[1:]
    return f"{mantissa}e{sign}{int(exponent)}"


def well_formed(text: str) -> None:
    for index, char in enumerate(text):
        code = ord(char)
        if 0xD800 <= code <= 0xDBFF:
            if index + 1 >= len(text):
                raise ValueError("invalid unicode")
            nxt = ord(text[index + 1])
            if not (0xDC00 <= nxt <= 0xDFFF):
                raise ValueError("invalid unicode")
        elif 0xDC00 <= code <= 0xDFFF:
            raise ValueError("invalid unicode")


def canonical(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return es_number(value)
    if isinstance(value, str):
        well_formed(value)
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(canonical(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = list(value)
        if any(not isinstance(key, str) for key in keys):
            raise TypeError("unsupported key")
        ordered = sorted(keys, key=lambda key: key.encode("utf-16-be"))
        parts: list[str] = []
        for key in ordered:
            if key in DANGEROUS:
                raise ValueError(f"dangerous key: {key}")
            well_formed(key)
            parts.append(json.dumps(key, ensure_ascii=False) + ":" + canonical(value[key]))
        return "{" + ",".join(parts) + "}"
    raise TypeError(f"unsupported value {type(value).__name__}")


def main() -> int:
    document = json.loads(VECTORS.read_text(encoding="utf-8"))
    failed = False
    for case in document["accept"]:
        actual = canonical(case["value"])
        if actual != case["canonical"]:
            failed = True
            print(f"FAIL {case['name']}\n  actual:   {actual}\n  expected: {case['canonical']}")
        else:
            print(f"ok {case['name']}")
    if failed:
        return 1
    # Programmatic rejects mirrored by the TypeScript suite.
    try:
        canonical({"__proto__": 1})
    except ValueError:
        print("ok dangerous-key")
    else:
        print("FAIL dangerous-key")
        return 1
    try:
        es_number(float("nan"))
    except ValueError:
        print("ok non-finite")
    else:
        print("FAIL non-finite")
        return 1
    print("vectors", len(document["accept"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
