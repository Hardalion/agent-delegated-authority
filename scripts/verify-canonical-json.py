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


def es_number(value: float | int) -> str:
    """ECMA-262 NumberToString for finite numbers, which is the RFC 8785 number format.

    JSON numbers are interpreted as IEEE-754 binary64 (ECMAScript Number) before
    serialization. Python ints are therefore coerced with float() — never emitted
    with arbitrary precision — so 9007199254740993 becomes 9007199254740992.

    This is not Python json.dumps. json.dumps(500.0) is `500.0`, json.dumps(1e-6)
    is `1e-06`, and json.dumps(1e20) stays in exponent form. JCS emits `500`,
    `0.000001`, and decimal notation through exponent 20.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("number required")
    # Match ECMAScript Number: coerce before formatting. Reject non-finite results
    # (values outside the binary64 range become inf / OverflowError).
    try:
        coerced = float(value)
    except OverflowError as exc:
        raise ValueError("non-finite") from exc
    if not math.isfinite(coerced):
        raise ValueError("non-finite")
    value = coerced
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    magnitude = -value if value < 0 else value
    scientific: str | None = None
    for precision in range(0, 17):
        candidate = format(magnitude, f".{precision}e")
        if float(candidate) == magnitude:
            scientific = candidate
            break
    if scientific is None:
        scientific = format(magnitude, ".16e")
    mantissa, exponent_text = scientific.split("e")
    exponent = int(exponent_text)
    digits = mantissa.replace(".", "")
    while len(digits) > 1 and digits.endswith("0"):
        shorter = digits[:-1]
        trial = shorter if len(shorter) == 1 else shorter[0] + "." + shorter[1:]
        if float(f"{trial}e{exponent}") == magnitude:
            digits = shorter
        else:
            break
    if -6 <= exponent <= 20:
        if exponent >= 0:
            if exponent >= len(digits) - 1:
                text = digits + ("0" * (exponent - (len(digits) - 1)))
            else:
                text = digits[: exponent + 1] + "." + digits[exponent + 1 :]
        else:
            text = "0." + ("0" * (-exponent - 1)) + digits
    else:
        body = digits if len(digits) == 1 else digits[0] + "." + digits[1:]
        exponent_sign = str(exponent) if exponent < 0 else f"+{exponent}"
        text = body + "e" + exponent_sign
    return sign + text


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
    for case in document["numbers"]:
        actual = es_number(case["value"])
        if actual != case["canonical"]:
            failed = True
            print(f"FAIL number {case['name']}\n  actual:   {actual}\n  expected: {case['canonical']}")
        else:
            print(f"ok number {case['name']}")
    if es_number(-0.0) != "0":
        failed = True
        print("FAIL number negative-zero")
    else:
        print("ok number negative-zero")
    # Counterexample from issue #3: Python int precision must not diverge from JS Number.
    if es_number(9007199254740993) != "9007199254740992":
        failed = True
        print("FAIL number two-53-plus-one-python-int")
    else:
        print("ok number two-53-plus-one-python-int")
    try:
        es_number(True)  # type: ignore[arg-type]
        failed = True
        print("FAIL boolean-as-number")
    except TypeError:
        print("ok boolean-as-number")
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
    try:
        es_number(10**400)
    except ValueError:
        print("ok overflow-to-inf")
    else:
        print("FAIL overflow-to-inf")
        return 1
    print("vectors", len(document["accept"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
