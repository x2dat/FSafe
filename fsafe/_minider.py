"""Minimal DER/ASN.1 reader for X.509 certificates — stdlib only.

Extracts just enough of a certificate for anomaly analysis: subject/issuer
(CN, O), SAN DNS names, validity window, key type/size, signature algorithm,
basic constraints. Not a general-purpose crypto library — a focused walker.
"""
from __future__ import annotations

import datetime

# object identifiers we care about
_OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.7": "L", "2.5.4.10": "O", "2.5.4.11": "OU",
    "2.5.4.6": "C", "2.5.4.8": "ST", "1.2.840.113549.1.9.1": "email",
}
_KEY_ALGOS = {
    "1.2.840.113549.1.1.1": "RSA", "1.2.840.10045.2.1": "EC",
    "1.2.840.10045.4.3.2": "EC", "1.3.101.112": "Ed25519",
}
_SIG_ALGOS = {
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}


def _read_len(data: bytes, i: int) -> tuple[int, int]:
    b = data[i]
    i += 1
    if b < 0x80:
        return b, i
    n = b & 0x7F
    if n == 0 or n > 4 or i + n > len(data):
        raise ValueError("bad DER length")
    return int.from_bytes(data[i:i + n], "big"), i + n


def _tlv(data: bytes, i: int) -> tuple[int, bytes, int]:
    """Return (tag, value, index-after) for one TLV at i."""
    if i >= len(data):
        raise ValueError("DER truncated")
    tag = data[i]
    ln, j = _read_len(data, i + 1)
    if j + ln > len(data):
        raise ValueError("DER length overruns buffer")
    return tag, data[j:j + ln], j + ln


def _children(data: bytes) -> list[tuple[int, bytes]]:
    """Direct children of a constructed value."""
    out, i = [], 0
    while i < len(data):
        tag, val, i = _tlv(data, i)
        out.append((tag, val))
    return out


def _oid(raw: bytes) -> str:
    if not raw:
        return ""
    parts = [raw[0] // 40, raw[0] % 40]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(val)
            val = 0
    return ".".join(map(str, parts))


def _name_fields(der_name: bytes) -> dict[str, str]:
    out: dict[str, str] = {}
    for tag, rdn in _children(der_name):  # SETs
        for _t, atv in _children(rdn):  # SEQUENCEs
            kids = _children(atv)
            if len(kids) >= 2 and kids[0][0] == 0x06:
                key = _OID_NAMES.get(_oid(kids[0][1]))
                if key and key not in out:
                    raw = kids[1][1]
                    out[key] = raw.decode("utf-8", "replace")
    return out


def _time(raw: bytes) -> str:
    s = raw.decode("ascii", "replace").rstrip("Z")
    if len(s) == 12:  # UTCTime YYMMDDHHMMSS
        yy = int(s[:2])
        s = ("19" if yy >= 50 else "20") + s
    try:
        dt = datetime.datetime.strptime(s[:14], "%Y%m%d%H%M%S")
        return dt.replace(tzinfo=datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return s


def _key_info(spki: bytes) -> dict:
    kids = _children(spki)
    if len(kids) < 2 or kids[0][0] != 0x30:
        return {}
    alg = _children(kids[0][1])
    algo = _KEY_ALGOS.get(_oid(alg[0][1]) if alg and alg[0][0] == 0x06 else "", "unknown")
    info = {"key_algo": algo}
    if algo == "RSA" and kids[1][0] == 0x03:
        bits = kids[1][1]
        if bits and bits[0] == 0:  # unused-bits byte
            bits = bits[1:]
        try:
            seq = _children(bits)[0][1]  # SEQUENCE(modulus, exponent)
            modulus = _children(seq)[0][1]
            info["key_bits"] = (len(modulus) - (1 if modulus and modulus[0] == 0 else 0)) * 8
        except (IndexError, ValueError):
            pass
    return info


def _extensions(exts_seq: bytes) -> dict:
    out: dict = {}
    for _tag, ext in _children(exts_seq):
        kids = _children(ext)
        if not kids or kids[0][0] != 0x06:
            continue
        oid = _oid(kids[0][1])
        octet = next((v for t, v in kids if t == 0x04), None)
        if octet is None:
            continue
        if oid == "2.5.29.17":  # subjectAltName
            try:
                # extnValue content is one SEQUENCE of GeneralNames
                names_seq = _children(octet)[0][1]
                out["san"] = [v.decode("utf-8", "replace") for t, v in _children(names_seq)
                              if t == 0x82]  # [2] dNSName
            except (ValueError, IndexError):
                pass
        elif oid == "2.5.29.19":  # basicConstraints
            try:
                seq = _children(octet)[0][1]
                out["is_ca"] = any(t == 0x01 and v and v[0] == 0xFF for t, v in _children(seq))
            except (ValueError, IndexError):
                pass
    return out


def cert_fields(der: bytes) -> dict:
    """Parse a DER certificate into the fields anomaly checks need.

    TBSCertificate has a deterministic layout (after the optional [0] version):
    serialNumber INTEGER, signature SEQ, issuer Name, validity SEQ,
    subject Name, subjectPublicKeyInfo SEQ, then optional [3] extensions.
    """
    _tag, body, _ = _tlv(der, 0)          # Certificate SEQUENCE
    kids = _children(body)
    if not kids:
        return {}
    tbs_kids = _children(_children(body)[0][1])   # tbsCertificate children
    out: dict = {"san": [], "is_ca": False}
    i = 0
    if i < len(tbs_kids) and tbs_kids[i][0] == 0xA0:
        i += 1                            # [0] version
    if i < len(tbs_kids) and tbs_kids[i][0] == 0x02:
        i += 1                            # serialNumber
    # 1) signature algorithm
    if i >= len(tbs_kids):
        return out
    alg = _children(tbs_kids[i][1])
    if alg and alg[0][0] == 0x06:
        out["sig_algo"] = _SIG_ALGOS.get(_oid(alg[0][1]), _oid(alg[0][1]))
    i += 1
    # 2) issuer Name
    if i >= len(tbs_kids):
        return out
    issuer_raw = tbs_kids[i][1]
    i += 1
    # 3) validity
    if i < len(tbs_kids):
        t = _children(tbs_kids[i][1])
        if len(t) >= 2:
            out["not_before"] = _time(t[0][1])
            out["not_after"] = _time(t[1][1])
        i += 1
    # 4) subject Name
    if i >= len(tbs_kids):
        return out
    subject_raw = tbs_kids[i][1]
    i += 1
    # 5) subjectPublicKeyInfo
    if i < len(tbs_kids):
        out.update(_key_info(tbs_kids[i][1]))
        i += 1
    # remaining: [1]/[2] unique ids (skip), [3] extensions
    while i < len(tbs_kids):
        tag, val = tbs_kids[i]
        if tag == 0xA3:
            try:
                seq = _children(val)[0][1]
                out.update(_extensions(seq))
            except (ValueError, IndexError):
                pass
        i += 1
    if subject_raw is not None:
        subj = _name_fields(subject_raw)
        out["subject_cn"] = subj.get("CN", "")
        out["subject_org"] = subj.get("O", "")
    if issuer_raw is not None:
        issuer = _name_fields(issuer_raw)
        out["issuer_cn"] = issuer.get("CN", "")
        out["issuer_org"] = issuer.get("O", "")
        out["self_signed"] = (issuer_raw == subject_raw and bool(issuer_raw))
    return out
