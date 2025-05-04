import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import json
import os
from hashlib import pbkdf2_hmac
import time

# Generate a key (this should be stored securely in production)
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Global variables
stored_data = {}  # Multi-user storage
failed_attempts = 0
last_failed_attempt_time = None
LOCKOUT_TIME = 60  # 1 minute lockout after 3 failed attempts

# Load data from JSON file
def load_data_from_file():
    global stored_data
    try:
        with open("stored_data.json", "r") as file:
            stored_data = json.load(file)
    except FileNotFoundError:
        stored_data = {}

# Save data to JSON file
def save_data_to_file():
    with open("stored_data.json", "w") as file:
        json.dump(stored_data, file)

# Hash passkey using PBKDF2
def hash_passkey_pbkdf2(passkey):
    salt = os.urandom(16)  # A unique salt for each passkey
    return pbkdf2_hmac('sha256', passkey.encode(), salt, 100000).hex()

# Encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    global failed_attempts, last_failed_attempt_time
    
    if check_lockout():
        return None
    
    hashed_passkey = hash_passkey_pbkdf2(passkey)
    
    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    
    failed_attempts += 1
    record_failed_attempt()
    return None

# Check lockout status
def check_lockout():
    global last_failed_attempt_time
    if last_failed_attempt_time:
        time_elapsed = time.time() - last_failed_attempt_time
        if time_elapsed < LOCKOUT_TIME:
            remaining_time = LOCKOUT_TIME - time_elapsed
            st.warning(f"🔒 Too many failed attempts. Please try again in {remaining_time:.0f} seconds.")
            return True
        else:
            last_failed_attempt_time = None
            return False
    return False

# Record failed attempts
def record_failed_attempt():
    global last_failed_attempt_time
    if failed_attempts >= 3:
        last_failed_attempt_time = time.time()

# Store user data
def store_user_data(username, data, passkey):
    hashed_passkey = hash_passkey_pbkdf2(passkey)
    encrypted_text = encrypt_data(data, passkey)
    stored_data[username] = {"encrypted_text": encrypted_text, "passkey": hashed_passkey}
    save_data_to_file()

# Retrieve user data
def retrieve_user_data(username, passkey):
    if username in stored_data:
        return decrypt_data(stored_data[username]["encrypted_text"], passkey)
    return None

# Streamlit UI
st.title("🔒 Secure Data Encryption System")
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

load_data_from_file()

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    username = st.text_input("Enter Username:")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if username and user_data and passkey:
            store_user_data(username, user_data, passkey)
            st.success(f"✅ Data for {username} stored securely!")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    username = st.text_input("Enter Username:")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if username and encrypted_text and passkey:
            decrypted_text = retrieve_user_data(username, passkey)
            if decrypted_text:
                st.success(f"✅ Decrypted Data: {decrypted_text}")
            else:
                st.error(f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}")
                if failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to Login Page.")
                    st.experimental_rerun()
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect password!")
