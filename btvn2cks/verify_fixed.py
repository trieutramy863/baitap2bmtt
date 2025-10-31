#!/usr/bin/env python3
"""
verify_fixed.py
Kiểm tra chữ ký PDF PKCS#7 (/Contents <...>, /ByteRange [...]>)
+ Tính hash theo ByteRange
+ So sánh messageDigest trong PKCS#7
+ Verify signature (signedAttrs)
"""

import sys, os, re, hashlib
from asn1crypto import cms, x509 as asn1_x509
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


# ===============================
#  🟦 1. TÁCH /ByteRange và /Contents từ PDF
# ===============================
def extract_pdf_contents(pdf_path):
    data = open(pdf_path, "rb").read()
    # tìm ByteRange và Contents
    m = re.search(rb"/ByteRange\s*\[([0-9\s]+)\].*?/Contents\s*<([0-9A-Fa-f\s\r\n]+)>",
                  data, re.DOTALL)
    if not m:
        raise ValueError("❌ Không tìm thấy ByteRange/Contents trong PDF")

    br = [int(x) for x in m.group(1).split()]
    contents_hex = re.sub(rb"[^0-9A-Fa-f]", b"", m.group(2))
    pkcs7_der = bytes.fromhex(contents_hex.decode("ascii"))
    return data, br, pkcs7_der


# ===============================
#  🟦 2. HASH theo ByteRange
# ===============================
def compute_digest(pdf_bytes, br):
    a, b, c, d = br
    m = hashlib.sha256()
    m.update(pdf_bytes[a:a+b])
    m.update(pdf_bytes[c:c+d])
    return m.digest()


# ===============================
#  🔥 VERIFY CHỮ KÝ
# ===============================
def verify(pdf_path):
    pdf_bytes, br, pkcs7_der = extract_pdf_contents(pdf_path)

    computed_digest = compute_digest(pdf_bytes, br)
    print("SHA256 (ByteRange) =", computed_digest.hex())

    ci = cms.ContentInfo.load(pkcs7_der)
    sd = ci["content"]
    signer_info = sd["signer_infos"][0]

    # lấy cert chứa public key để verify
    cert = sd["certificates"][0].chosen
    cert_crypto = load_der_x509_certificate(cert.dump())

    # lấy messageDigest trong PKCS7
    md_pkcs7 = None
    for attr in signer_info["signed_attrs"]:
        if attr["type"].dotted == "1.2.840.113549.1.9.4":
            md_pkcs7 = bytes(attr["values"][0].native)
            break

    print("SHA256 (PKCS7)    =", md_pkcs7.hex())

    if md_pkcs7 != computed_digest:
        print("❌ HASH KHÔNG KHỚP → PDF bị sửa hoặc ký sai")
        return False

    print("✅ HASH TRÙNG NHAU")

    # verify chữ ký
    cert_crypto.public_key().verify(
        signer_info["signature"].native,
        signer_info["signed_attrs"].dump(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    print("✅ CHỮ KÝ HỢP LỆ (VN-PTD PKCS#7)")
    print("👤 Người ký:", cert_crypto.subject.rfc4514_string())
    return True


# ===============================
#  RUN
# ===============================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python verify_fixed.py signed_output.pdf")
        sys.exit(1)

    verify(sys.argv[1])
