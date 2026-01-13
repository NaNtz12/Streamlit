import streamlit as st
import hashlib, json, base64, qrcode
from io import BytesIO
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# RSA Key Pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

st.title("Digital Signature & QRIS")

menu = st.radio("Mode", ["Pengirim", "Penerima"])

if menu == "Pengirim":
    pesan = st.text_area("Pesan")

    if st.button("Generate QR"):
        hash_pesan = hashlib.sha256(pesan.encode()).digest()
        signature = private_key.sign(
            hash_pesan,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        payload = {
            "pesan": pesan,
            "signature": base64.b64encode(signature).decode()
        }

        qr_text = json.dumps(payload)
        qr_img = qrcode.make(qr_text)

        buf = BytesIO()
        qr_img.save(buf)
        st.image(buf.getvalue())
        st.code(qr_text)

if menu == "Penerima":
    qr_text = st.text_area("Isi QR")

    if st.button("Verifikasi"):
        payload = json.loads(qr_text)
        pesan = payload["pesan"]
        signature = base64.b64decode(payload["signature"])

        try:
            public_key.verify(
                signature,
                hashlib.sha256(pesan.encode()).digest(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            st.success("Signature VALID")
        except InvalidSignature:
            st.error("Signature TIDAK VALID")
