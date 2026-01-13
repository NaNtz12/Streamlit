import streamlit as st
import hashlib
import json
import base64
import cv2
import numpy as np
from PIL import Image

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from keys import npm_20221310071_load_or_create_keys

_, public_key = npm_20221310071_load_or_create_keys()


# =========================
# FUNGSI (PREFIX NPM)
# =========================
def npm_20221310071_hash_pesan(pesan: str) -> bytes:
    return hashlib.sha256(pesan.encode()).digest()


def npm_20221310071_verify_signature(pesan: str, signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64)
        hash_pesan = npm_20221310071_hash_pesan(pesan)

        public_key.verify(
            signature,
            hash_pesan,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def npm_20221310071_decode_qr_image(image: Image.Image) -> str | None:
    img_array = np.array(image.convert("RGB"))
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(img_array)
    return data if data else None

# =========================
# STREAMLIT UI
# =========================
st.set_page_config(
    page_title="Penerima Pesan Digital",
    page_icon="📥",
    layout="centered"
)

st.title("📥 Penerima Pesan Digital")
st.caption("Verifikasi Digital Signature dari QRIS")
st.markdown("---")

mode = st.radio(
    "Pilih metode input QR",
    [
        "📷 Upload Gambar QR",
        "📄 Upload File QR (TXT / JSON)",
        "📝 Paste Teks QR"
    ]
)

qr_text = None

# =========================
# UPLOAD GAMBAR QR
# =========================
if mode == "📷 Upload Gambar QR":
    uploaded_img = st.file_uploader(
        "Upload gambar QR (PNG / JPG)",
        type=["png", "jpg", "jpeg"]
    )

    if uploaded_img:
        image = Image.open(uploaded_img)
        st.image(image, caption="QR yang diunggah", width=400)

        qr_text = npm_20221310071_decode_qr_image(image)
        if qr_text:
            st.success("✅ QR berhasil dibaca dari gambar")
        else:
            st.error("❌ QR tidak dapat dibaca")

# =========================
# UPLOAD FILE QR
# =========================
elif mode == "📄 Upload File QR (TXT / JSON)":
    uploaded_file = st.file_uploader(
        "Upload file QR",
        type=["txt", "json"]
    )

    if uploaded_file:
        qr_text = uploaded_file.read().decode("utf-8")
        st.success("✅ File QR berhasil dibaca")
        st.code(qr_text, language="json")

# =========================
# PASTE TEKS QR
# =========================
else:
    qr_text = st.text_area(
        "Tempel isi QR di sini",
        height=180,
        placeholder="Tempel teks QR (JSON payload)"
    )

st.markdown("---")

# =========================
# VERIFIKASI
# =========================
if st.button("🔎 Verifikasi Digital Signature", use_container_width=True):
    if not qr_text:
        st.warning("⚠️ QR belum tersedia")
    else:
        try:
            payload = json.loads(qr_text)
            pesan = payload["pesan"]
            signature = payload["signature"]

            valid = npm_20221310071_verify_signature(pesan, signature)

            if valid:
                st.success("✅ Signature VALID — Pesan Asli")
                st.markdown("### 📄 Isi Pesan")
                st.info(pesan)
            else:
                st.error("❌ Signature TIDAK VALID")

        except Exception as e:
            st.error(f"⚠️ Terjadi kesalahan: {e}")
