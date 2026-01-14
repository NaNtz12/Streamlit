import streamlit as st
import hashlib, json, base64, qrcode
from io import BytesIO
import cv2, numpy as np
from PIL import Image

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from keys import npm_20221310071_load_or_create_keys

private_key, public_key = npm_20221310071_load_or_create_keys()

# =========================
# FUNGSI (PREFIX NPM)
# =========================
def npm_20221310071_hash_pesan(pesan: str) -> bytes:
    return hashlib.sha256(pesan.encode()).digest()


def npm_20221310071_generate_signature(pesan: str) -> str:
    signature = private_key.sign(
        npm_20221310071_hash_pesan(pesan),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()


def npm_20221310071_verify_signature(pesan: str, signature_b64: str) -> bool:
    try:
        public_key.verify(
            base64.b64decode(signature_b64),
            npm_20221310071_hash_pesan(pesan),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def npm_20221310071_decode_qr(image: Image.Image):
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(
        np.array(image.convert("RGB"))
    )
    return data if data else None


# =========================
# UI CONFIG
# =========================
st.set_page_config(
    page_title="Digital Signature RSA",
    page_icon="🔐",
    layout="wide"
)

# =========================
# SIDEBAR MENU
# =========================
st.sidebar.title("🔐 Digital Signature")
menu = st.sidebar.radio(
    "Menu",
    ["📤 Pengirim Pesan", "📥 Penerima Pesan"]
)

# =========================
# HEADER
# =========================
st.markdown(
    "<h1 style='text-align:center;'>Digital Signature & QRIS</h1>",
    unsafe_allow_html=True
)
st.markdown(
    "<p style='text-align:center;color:gray;'>RSA + SHA-256 | Streamlit App</p>",
    unsafe_allow_html=True
)
st.markdown("---")

# =========================
# PENGIRIM
# =========================
if menu == "📤 Pengirim Pesan":
    st.subheader("📤 Pengirim Pesan Digital")

    pesan = st.text_area(
        "Masukkan Pesan",
        height=160,
        placeholder="Contoh: Dokumen ini adalah dokumen resmi institusi"
    )

    if st.button("🔏 Generate Digital Signature & QRIS", use_container_width=True):
        if pesan.strip() == "":
            st.warning("Pesan tidak boleh kosong")
        else:
            payload = {
                "pesan": pesan,
                "signature": npm_20221310071_generate_signature(pesan)
            }

            qr_text = json.dumps(payload)
            qr_img = qrcode.make(qr_text)

            buf = BytesIO()
            qr_img.save(buf)

            col1, col2 = st.columns([1, 1])
            with col1:
                st.image(buf.getvalue(), caption="QRIS Digital Signature", width=300)
            with col2:
                st.markdown("### Payload QR")
                st.code(payload, language="json")

# =========================
# PENERIMA
# =========================
if menu == "📥 Penerima Pesan":
    st.subheader("📥 Verifikasi Digital Signature")

    metode = st.radio(
        "Metode Input QR",
        ["Upload Gambar QR", "Upload File QR", "Paste Teks QR"]
    )

    qr_text = None

    if metode == "Upload Gambar QR":
        file = st.file_uploader("Upload gambar QR", ["png", "jpg", "jpeg"])
        if file:
            image = Image.open(file)
            st.image(image, width=300)
            qr_text = npm_20221310071_decode_qr(image)

    elif metode == "Upload File QR":
        file = st.file_uploader("Upload file QR (TXT / JSON)", ["txt", "json"])
        if file:
            qr_text = file.read().decode()

    else:
        qr_text = st.text_area("Tempel isi QR di sini", height=180)

    if st.button("🔎 Verifikasi", use_container_width=True):
        try:
            payload = json.loads(qr_text)
            valid = npm_20221310071_verify_signature(
                payload["pesan"],
                payload["signature"]
            )

            if valid:
                st.success("✅ Signature VALID")
                st.info(payload["pesan"])
            else:
                st.error("❌ Signature TIDAK VALID")

        except Exception as e:
            st.error(f"Error: {e}")
