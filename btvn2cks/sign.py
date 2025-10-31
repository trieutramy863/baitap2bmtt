import os, datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization.pkcs7 import PKCS7SignatureBuilder, PKCS7Options
from cryptography import x509
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.generic import DictionaryObject, NameObject, ArrayObject, TextStringObject, NumberObject, StreamObject
from PIL import Image, ImageDraw, ImageFont, ImageOps

# === CONFIG (đúng thư mục của bạn) ===
BASE = r"D:\btvn2cks"     # ✅ đúng với ảnh bạn gửi
pdf_in = os.path.join(BASE, "input.pdf")
pdf_out = os.path.join(BASE, "signed_output.pdf")
key_file = os.path.join(BASE, "private_key.pem")
cert_file = os.path.join(BASE, "cert.pem")
root_file = os.path.join(BASE, "cert.pem")
sign_img = os.path.join(BASE, "chuky.jpg")
appearance_img = os.path.join(BASE, "appearance.jpg")

DEFAULT_PHONE = "0345678210"
DEFAULT_LOCATION = "VIỆT NAM"
DISPLAY_NAME = "TRIỆU TRÀ MY"      # ✅ Tên của bạn

# === VẼ CHỮ KÝ ===
def make_appearance(out_path, sign_path, phone, location, name_display):
    W, H = 420, 150
    canvas = Image.new("RGB", (W, H), (255, 255, 255))
    draw = ImageDraw.Draw(canvas)
    font_path = "C:/Windows/Fonts/arial.ttf"
    font_small = ImageFont.truetype(font_path, 12)
    font_bold = ImageFont.truetype(font_path, 13)

    draw.text((12, 10), f"SĐT: {phone}", font=font_small, fill=(0, 0, 0))
    draw.text((12, 28), f"Ngày ký: {datetime.datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", font=font_small, fill=(0, 0, 0))
    draw.text((12, 46), f"Location: {location}", font=font_small, fill=(0, 0, 0))

    sig = Image.open(sign_path).convert("RGBA")
    bbox = ImageOps.invert(sig.convert("RGB")).getbbox()
    if bbox: sig = sig.crop(bbox)
    sig = sig.resize((160, int(sig.size[1] * 160 / sig.size[0])), Image.LANCZOS)

    sig_x, sig_y = W - sig.size[0] - 20, 5
    canvas.paste(sig, (sig_x, sig_y), sig)
    draw.text((sig_x + 10, sig_y + sig.size[1] + 5), name_display.upper(), font=font_bold, fill=(0, 0, 0))

    canvas.save(out_path, format="JPEG", quality=95)

make_appearance(appearance_img, sign_img, DEFAULT_PHONE, DEFAULT_LOCATION, DISPLAY_NAME)

# === LOAD CERT & KEY ===
with open(key_file, "rb") as f: key = load_pem_private_key(f.read(), password=None)
with open(cert_file, "rb") as f: cert = x509.load_pem_x509_certificate(f.read())
with open(root_file, "rb") as f: root_cert = x509.load_pem_x509_certificate(f.read())

# === TẠO TRƯỜNG CHỮ KÝ PDF ===
reader = PdfReader(pdf_in)
writer = PdfWriter()
for p in reader.pages: writer.add_page(p)
page = writer.pages[-1]

rect_w, rect_h = 420, 150
page_w, page_h = float(page.mediabox.width), float(page.mediabox.height)
x1, y1 = page_w - rect_w - 50, 50
x2, y2 = page_w - 50, 50 + rect_h

sig_field = DictionaryObject({
    NameObject("/FT"): NameObject("/Sig"),
    NameObject("/Type"): NameObject("/Annot"),
    NameObject("/Subtype"): NameObject("/Widget"),
    NameObject("/T"): TextStringObject("Signature1"),
    NameObject("/Rect"): ArrayObject([NumberObject(x1), NumberObject(y1), NumberObject(x2), NumberObject(y2)]),
})
sig_ref = writer._add_object(sig_field)
if "/Annots" not in page: page[NameObject("/Annots")] = ArrayObject()
page[NameObject("/Annots")].append(sig_ref)
sig_field[NameObject("/P")] = page.indirect_reference

# === THÊM HÌNH ẢNH CHỮ KÝ ===
with open(appearance_img, "rb") as f: img_bytes = f.read()
img_obj = StreamObject()
img_obj._data = img_bytes
img_obj.update({
    NameObject("/Type"): NameObject("/XObject"),
    NameObject("/Subtype"): NameObject("/Image"),
    NameObject("/Width"): NumberObject(420),
    NameObject("/Height"): NumberObject(150),
    NameObject("/ColorSpace"): NameObject("/DeviceRGB"),
    NameObject("/BitsPerComponent"): NumberObject(8),
    NameObject("/Filter"): NameObject("/DCTDecode"),
})
img_ref = writer._add_object(img_obj)

form_stream = StreamObject()
form_stream._data = b"q\n420 0 0 150 0 0 cm\n/Im1 Do\nQ\n"
form_stream.update({
    NameObject("/Type"): NameObject("/XObject"),
    NameObject("/Subtype"): NameObject("/Form"),
    NameObject("/BBox"): ArrayObject([NumberObject(0), NumberObject(0), NumberObject(420), NumberObject(150)]),
    NameObject("/Resources"): DictionaryObject({
        NameObject("/XObject"): DictionaryObject({NameObject("/Im1"): img_ref})
    }),
})
form_ref = writer._add_object(form_stream)
sig_field.update({NameObject("/AP"): DictionaryObject({NameObject("/N"): form_ref})})

acro = DictionaryObject({NameObject("/Fields"): ArrayObject([sig_ref]), NameObject("/SigFlags"): NumberObject(3)})
writer._root_object.update({NameObject("/AcroForm"): acro})

unsigned_pdf = os.path.join(BASE, "temp_unsigned.pdf")
with open(unsigned_pdf, "wb") as f: writer.write(f)

# === TẠO /ByteRange & /Contents ===
with open(unsigned_pdf, "rb") as f: data = f.read()

placeholder = b"0" * 8192
sig_obj = (
    b"\n<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached"
    + f"\n/Name ({DISPLAY_NAME})".encode()
    + b"\n/Reason (Document signing)"
    + b"\n/Location (" + DEFAULT_LOCATION.encode() + b")"
    + f"\n/M (D:{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S+00\'00\'')})".encode()
    + b"\n/ByteRange [0 0000000000 0000000000 0000000000]"
    + b"\n/Contents <" + placeholder + b"> >>"
)

unsigned = data + sig_obj

cont_start = unsigned.find(b"<" + placeholder + b">")
br = [0, cont_start - 1, cont_start + len(placeholder) + 2, len(unsigned) - (cont_start + len(placeholder) + 2)]
to_hash = unsigned[br[0]:br[0]+br[1]] + unsigned[br[2]:br[2]+br[3]]

pkcs7 = (
    PKCS7SignatureBuilder()
    .set_data(to_hash)
    .add_signer(cert, key, hashes.SHA256())
    .add_certificate(cert)
    .add_certificate(root_cert)
    .sign(serialization.Encoding.DER, [PKCS7Options.DetachedSignature])
)
sig_hex = pkcs7.hex().encode()
br_text = f"[0 {br[1]} {br[2]} {br[3]}]".encode()
signed_pdf = unsigned.replace(b"[0 0000000000 0000000000 0000000000]", br_text)
signed_pdf = signed_pdf.replace(placeholder, sig_hex.ljust(len(placeholder), b"0"))

with open(pdf_out, "wb") as f: f.write(signed_pdf)

print("✅ PDF ký thành công!")
print("📄 File xuất ra:", pdf_out)
