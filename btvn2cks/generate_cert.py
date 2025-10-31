from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta

# -------------------------------
# 1. Tạo private key RSA (2048 bit)
# -------------------------------
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

with open("private_key.pem", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# -------------------------------
# 2. Tạo chứng chỉ self-signed
#    SUBJECT = "Trieu Tra My"
# -------------------------------
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ho Chi Minh"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "District 1"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Private Signer"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Trieu Tra My"),   # ✅ tên đã đổi
])

cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # 10 năm
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(key, hashes.SHA256())  # ✅ Hash SHA-256
)

with open("cert.pem", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))

print("\n✅ ĐÃ TẠO private_key.pem & cert.pem (Tên: Trieu Tra My)")
