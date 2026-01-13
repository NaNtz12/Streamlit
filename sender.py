import streamlit as st
import hashlib
import json
import base64
import qrcode
from io import BytesIO

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from keys import npm_20221310071_load_or_create_keys

private_key, _ = npm_20221310071_load_or_create_keys()


# =========================
# FUNGSI (PREFIX NPM)
# =========================
def npm_20221310071_hash_pesan(pesan: str) -> bytes:
    return hashlib.sha256(pesan.encode()).digest()


def npm_20221310071_generate_signature(pesan: str) -> str:
    hash_pesan = npm_20221310071_hash_pesan(pesan)

    signature = private_key.sign(
        hash_pesan,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.b64encode(signature).decode("utf-8")


def npm_20221310071_generate_qr_payload(pesan: str) -> str:
    payload = {
        "pesan": pesan,
        "signature": npm_20221310071_generate_signature(pesan)
    }
    return json.dumps(payload)

# =========================
# STREAMLIT UI
# =========================
st.set_page_config(
    page_title="Pengirim Pesan Digital",
    page_icon="📤",
    layout="centered"
)

st.title("📤 Pengirim Pesan Digital")
st.caption("Generate Digital Signature & QRIS (RSA + SHA-256)")
st.markdown("---")

pesan = st.text_area(
    "Masukkan Pesan Digital",
    height=150,
    placeholder="Contoh: Dokumen ini adalah dokumen resmi institusi"
)

if st.button("🔏 Generate Digital Signature & QRIS", use_container_width=True):
    if pesan.strip() == "":
        st.warning("⚠️ Pesan tidak boleh kosong")
    else:
        qr_text = npm_20221310071_generate_qr_payload(pesan)

        qr_img = qrcode.make(qr_text)
        buf = BytesIO()
        qr_img.save(buf)

        st.success("✅ QRIS berhasil dibuat")
        st.image(buf.getvalue(), caption="QRIS Digital Signature", width=400)
        st.markdown("### 📦 Payload QRIS")
        st.code(qr_text, language="json")
