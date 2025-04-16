import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# --- Config & Theme ---
st.set_page_config(page_title="🔐 Secure Data", layout="centered")

# --- File to store encrypted data ---
DATA_FILE = "secure_data.json"

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

# --- Functions for encryption and hashing ---
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()

cipher = Fernet(st.session_state.fernet_key)

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- Session-based login ---
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

# --- Navigation ---
menu = ["Home", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("📍 Navigate", menu)

# --- Home Page ---
if choice == "Home":
    st.title("🔐 Secure Data Encryption System")
    st.markdown("### 🛡️ Welcome to Your Encrypted Storage System")
    st.markdown("""
        - ✅ **Store & retrieve sensitive information**
        - 🔐 **Encrypted with your unique passkey**
        - 👁️‍🗨️ **Secure, simple & local**
        - 🔓 **Login to start encrypting**
    """)
    st.image("https://cdn-icons-png.flaticon.com/512/3064/3064197.png", width=150)

# --- Login Page ---
elif choice == "Login":
    st.title("🔐 Login Required")
    password = st.text_input("Enter Master Password", type="password")
    if st.button("Login"):
        if password == "admin123":  # you can change this
            st.session_state.logged_in = True
            st.success("✅ Login Successful!")
        else:
            st.error("❌ Wrong password.")

# --- Store Data Page ---
elif choice == "Store Data":
    if not st.session_state.logged_in:
        st.warning("🔐 Please login first.")
        st.stop()

    st.title("📥 Store Your Data Securely")
    label = st.text_input("Enter a label (e.g. Note1):")
    user_data = st.text_area("Your data here:")
    passkey = st.text_input("Create a passkey:", type="password")

    if st.button("Encrypt & Save"):
        if label and user_data and passkey:
            encrypted = encrypt_data(user_data)
            hashed = hash_passkey(passkey)
            stored = load_data()
            stored[label] = {"encrypted_text": encrypted, "passkey": hashed}
            save_data(stored)
            st.success(f"✅ Data saved with label: `{label}`")
        else:
            st.warning("⚠️ Please fill all fields.")

# --- Retrieve Data Page ---
elif choice == "Retrieve Data":
    if not st.session_state.logged_in:
        st.warning("🔐 Please login first.")
        st.stop()

    st.title("🔓 Retrieve Your Encrypted Data")
    label = st.text_input("Enter your saved label:")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        stored = load_data()
        if label in stored:
            record = stored[label]
            if hash_passkey(passkey) == record["passkey"]:
                decrypted = decrypt_data(record["encrypted_text"])
                st.success("✅ Successfully Decrypted!")
                st.text_area("🔍 Your Data:", decrypted, height=120)
            else:
                st.error("❌ Incorrect passkey.")
        else:
            st.error("⚠️ No data found with that label.")
