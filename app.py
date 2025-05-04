import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os

# Configuration
st.set_page_config(page_title="Secure Data Encryption", layout="wide")

# Generate Key
key_file = "secret.key"
if not os.path.exists(key_file):
    key = Fernet.generate_key()
    with open(key_file, 'wb') as f:
        f.write(key)
else:
    with open(key_file, 'rb') as f:
        key = f.read()
fernet = Fernet(key)

# In-Memory Database
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'attempts' not in st.session_state:
    st.session_state.attempts = 0
if 'login_required' not in st.session_state:
    st.session_state.login_required = False

# Helper Functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(data, passkey):
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(cipher_text, passkey):
    return fernet.decrypt(cipher_text.encode()).decode()

# ✅ Home Page Function
def home():
    st.title("🔐 Secure Data Encryption System")
    st.markdown("""
    Use this system to encrypt and store sensitive data securely. You can retrieve it with the correct passkey. After three failed attempts, reauthorization is required.
    """)

    st.image("https://cdn-icons-png.flaticon.com/512/2889/2889676.png", width=120)

    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔏 Store New Data"):
            st.session_state.page = 'insert'
    with col2:
        if st.button("🔓 Retrieve Data"):
            st.session_state.page = 'retrieve'

# Insert Page
def insert_data():
    st.header("🔏 Store Your Data Securely")
    text = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Encrypt & Store"):
        if text and passkey:
            hashed = hash_passkey(passkey)
            encrypted = encrypt_data(text, passkey)
            st.session_state.stored_data[hashed] = {"encrypted": encrypted, "passkey": hashed}
            st.success("✅ Data Encrypted and Stored Securely!")
        else:
            st.error("❗ Both fields are required!")

# Retrieve Page
def retrieve_data():
    st.header("🔓 Retrieve Your Data")
    passkey = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        hashed = hash_passkey(passkey)
        if hashed in st.session_state.stored_data:
            encrypted = st.session_state.stored_data[hashed]['encrypted']
            try:
                decrypted = decrypt_data(encrypted, passkey)
                st.success("✅ Data Decrypted Successfully!")
                st.code(decrypted, language='text')
                st.session_state.attempts = 0
            except:
                st.error("❗ Incorrect decryption key")
                st.session_state.attempts += 1
        else:
            st.error("❗ Passkey not recognized")
            st.session_state.attempts += 1

        if st.session_state.attempts >= 3:
            st.warning("🔒 Too many attempts. Login required.")
            st.session_state.login_required = True
            st.session_state.page = 'login'

# Login Page
def login():
    st.header("🔑 Reauthorization Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "admin":
            st.session_state.attempts = 0
            st.session_state.login_required = False
            st.session_state.page = 'home'
            st.success("✅ Logged in!")
        else:
            st.error("❗ Invalid credentials")

# Main App Logic
if 'page' not in st.session_state:
    st.session_state.page = 'home'

# Sidebar Menu
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/3655/3655583.png", width=100)
    st.title("🛡️ Menu")
    if st.button("🏠 Home"):
        st.session_state.page = 'home'
    if st.button("📥 Insert Data"):
        st.session_state.page = 'insert'
    if st.button("📤 Retrieve Data"):
        st.session_state.page = 'retrieve'

# Page Routing
if st.session_state.login_required:
    login()
elif st.session_state.page == 'home':
    home()
elif st.session_state.page == 'insert':
    insert_data()
elif st.session_state.page == 'retrieve':
    retrieve_data()
