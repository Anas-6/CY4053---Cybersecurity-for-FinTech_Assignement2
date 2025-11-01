"""
streamlit_app.py
Secure FinTech mini-app for CY4053 Assignment 2
Enhanced version with better validation, sanitization, and feedback.
"""

import streamlit as st
import sqlite3
import bcrypt
import re
import os
import base64
from cryptography.fernet import Fernet
from datetime import datetime
import pandas as pd
from io import BytesIO

# ---------------------------
# Config / Paths
# ---------------------------
DB_PATH = "secure_fintech.db"
KEY_PATH = "secret.key"
ALLOWED_UPLOAD_TYPES = ["png", "jpg", "jpeg", "pdf", "csv", "txt"]

# ---------------------------
# UI Theme / CSS
# ---------------------------
def inject_css():
    st.markdown(
        """
        <style>
        .stApp {
            background: radial-gradient(circle at 10% 10%, #041628 0%, #071428 25%, #02040a 100%);
            color: #cfefff;
            font-family: "Inter", sans-serif;
        }
        .neon-card {
            background: rgba(10, 20, 30, 0.55);
            border-radius: 12px;
            padding: 18px;
            box-shadow: 0 0 20px rgba(0,255,200,0.04), 0 0 6px rgba(0,255,200,0.06) inset;
            border: 1px solid rgba(0,255,200,0.08);
        }
        .stButton>button {
            background: linear-gradient(90deg,#00fff0,#00a3ff);
            color: #001217;
            font-weight: 600;
            border-radius: 8px;
            padding: 8px 14px;
            box-shadow: 0 2px 10px rgba(0,160,255,0.15);
        }
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background: rgba(255,255,255,0.03);
            color: #dff7ff;
            border-radius: 6px;
            padding: 8px;
        }
        h1, h2, h3 {
            color: #bff7ff;
            text-shadow: 0 0 6px rgba(0,255,220,0.06);
        }
        .neon-accent { color: #86fff2; font-weight:700; }
        </style>
        """,
        unsafe_allow_html=True,
    )

# ---------------------------
# KEY / DB INIT
# ---------------------------
def load_or_create_key():
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as f:
            f.write(key)
        return key

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS wallets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        wallet_name TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )
    """)
    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        timestamp TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

# ---------------------------
# Security helpers
# ---------------------------
def hash_password(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt())

def verify_password(pw: str, pw_hash: bytes) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), pw_hash)
    except Exception:
        return False

PASSWORD_REGEX = re.compile(
    r"^(?=.{8,})(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).*$"
)
def is_strong_password(pw: str) -> bool:
    return bool(PASSWORD_REGEX.match(pw))

EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
def is_valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

# --- Improved sanitization ---
def sanitize_text(s: str) -> str:
    s = s.strip()
    if len(s) > 2000:
        s = s[:2000]
    s = re.sub(r"(?i)<.*?>", "", s)  # remove all tags
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    return s

# ---------------------------
# Audit Logging
# ---------------------------
def log_action(user_id, action, details=None):
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO audit_logs (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)",
                  (user_id, action, details, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    except Exception:
        pass

# ---------------------------
# User operations
# ---------------------------
def register_user(username, email, password):
    username = sanitize_text(username)
    email = sanitize_text(email)
    if not username or not email or not password:
        return False, "All fields are required."
    if not is_valid_email(email):
        return False, "Invalid email format."
    if not is_strong_password(password):
        return False, "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character."
    try:
        conn = get_db_connection()
        c = conn.cursor()
        pw_hash = hash_password(password)
        c.execute("INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                  (username, email, pw_hash, datetime.utcnow().isoformat()))
        conn.commit()
        user_id = c.lastrowid
        conn.close()
        log_action(user_id, "register", f"New user {username}")
        return True, "Registration successful."
    except sqlite3.IntegrityError:
        return False, "Username or email already exists."
    except Exception:
        return False, "Registration failed due to system error."

def get_user_by_username(username):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row

def get_user_by_id(user_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    conn.close()
    return row

def update_user_email(user_id, new_email):
    if not is_valid_email(new_email):
        return False, "Invalid email format."
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
        conn.commit()
        conn.close()
        log_action(user_id, "profile_update", "email_changed")
        return True, "Email updated successfully."
    except sqlite3.IntegrityError:
        return False, "Email already in use."
    except Exception:
        return False, "Email update failed."

def change_user_password(user_id, old_pw, new_pw):
    if not is_strong_password(new_pw):
        return False, "New password must be strong (8+ chars, upper, lower, number, special)."
    user = get_user_by_id(user_id)
    if not user:
        return False, "User not found."
    if not verify_password(old_pw, user["password_hash"]):
        return False, "Old password incorrect."
    try:
        new_hash = hash_password(new_pw)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        conn.commit()
        conn.close()
        log_action(user_id, "password_change", "user_changed_password")
        return True, "Password changed successfully."
    except Exception:
        return False, "Password update failed."

# ---------------------------
# Encryption / Wallet
# ---------------------------
fernet = None
def init_crypto():
    global fernet
    key = load_or_create_key()
    fernet = Fernet(key)

def encrypt_data(text: str) -> bytes:
    return fernet.encrypt(text.encode("utf-8"))

def decrypt_data(token: bytes) -> str:
    return fernet.decrypt(token).decode("utf-8")

def create_wallet(owner_id, wallet_name, data):
    try:
        enc = encrypt_data(data)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO wallets (owner_id, wallet_name, encrypted_data, created_at) VALUES (?, ?, ?, ?)",
                  (owner_id, wallet_name, enc, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        log_action(owner_id, "create_wallet", f"wallet:{wallet_name}")
        return True, "Wallet created successfully."
    except Exception:
        return False, "Wallet creation failed."

def get_wallets_for_user(owner_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, wallet_name, encrypted_data, created_at FROM wallets WHERE owner_id = ?", (owner_id,))
    rows = c.fetchall()
    conn.close()
    return rows

# ---------------------------
# File Upload
# ---------------------------
def validate_uploaded_file(uploaded):
    filename = uploaded.name
    ext = filename.split(".")[-1].lower()
    if ext not in ALLOWED_UPLOAD_TYPES:
        return False, f"File type .{ext} not allowed."
    if uploaded.size > 5 * 1024 * 1024:
        return False, "File too large (>5MB)."
    return True, "OK"

# ---------------------------
# UI Pages
# ---------------------------
def show_home():
    st.title("🔐 Secure FinTech Mini App — Cyber Edition")
    st.markdown("This app demonstrates secure coding concepts for FinTech cybersecurity testing.")
    st.divider()

def show_register():
    st.header("User Registration")
    st.caption("🔒 Password must include uppercase, lowercase, number, special character, and be at least 8 characters long.")
    with st.form("register_form", clear_on_submit=False):
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register")
        if submitted:
            if password != confirm:
                st.warning("Passwords do not match.")
            else:
                ok, msg = register_user(username, email, password)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

def show_login():
    st.header("User Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            try:
                if not username.strip() or not password.strip():
                    st.warning("Please enter both username and password.")
                else:
                    user = get_user_by_username(username)
                    if user and verify_password(password, user["password_hash"]):
                        st.session_state["user_id"] = user["id"]
                        st.session_state["username"] = user["username"]
                        st.success("Login successful.")
                        log_action(user["id"], "login", "User logged in")
                    else:
                        st.error("Invalid username or password.")
                        log_action(None, "login_failed", f"username_attempt:{sanitize_text(username)}")
            except Exception:
                st.error("Login error.")

def require_login():
    return "user_id" in st.session_state and st.session_state["user_id"]

def show_profile():
    st.header("Profile")
    user = get_user_by_id(st.session_state["user_id"])
    if not user:
        st.error("User not found.")
        return
    st.write(f"**Username:** {sanitize_text(user['username'])}")
    st.write(f"**Email:** {sanitize_text(user['email'])}")
    st.divider()
    st.subheader("Update Email")
    with st.form("email_form"):
        new_email = st.text_input("New email")
        if st.form_submit_button("Update"):
            ok, msg = update_user_email(user["id"], new_email)
            if ok: st.success(msg)
            else: st.error(msg)
    st.divider()
    st.subheader("Change Password")
    with st.form("pw_form"):
        old = st.text_input("Old password", type="password")
        new = st.text_input("New password", type="password")
        confirm = st.text_input("Confirm new password", type="password")
        if st.form_submit_button("Change"):
            if new != confirm:
                st.warning("New passwords do not match.")
            else:
                ok, msg = change_user_password(user["id"], old, new)
                if ok: st.success(msg)
                else: st.error(msg)

def show_wallets():
    st.header("Wallets (Encrypted Data)")
    st.divider()
    with st.form("create_wallet"):
        name = st.text_input("Wallet name")
        data = st.text_area("Private data")
        if st.form_submit_button("Create"):
            if not name or not data:
                st.error("All fields required.")
            else:
                ok, msg = create_wallet(st.session_state["user_id"], sanitize_text(name), sanitize_text(data))
                if ok: st.success(msg)
                else: st.error(msg)
    st.divider()
    wallets = get_wallets_for_user(st.session_state["user_id"])
    if not wallets:
        st.info("No wallets created yet.")
    else:
        for w in wallets:
            st.write(f"**{sanitize_text(w['wallet_name'])}** — created {w['created_at']}")
            if st.button(f"Decrypt Wallet {w['id']}", key=f"dec_{w['id']}"):
                try:
                    st.text_area("Decrypted data:", decrypt_data(w["encrypted_data"]), height=100)
                    log_action(st.session_state["user_id"], "wallet_decrypt", f"wallet:{w['id']}")
                except Exception:
                    st.error("Decryption failed.")

def show_file_upload():
    st.header("Secure File Upload")
    file = st.file_uploader("Upload file", type=ALLOWED_UPLOAD_TYPES)
    if file:
        ok, msg = validate_uploaded_file(file)
        if not ok:
            st.error(msg)
        else:
            st.success("File accepted.")
            st.write({"name": file.name, "size": file.size})

def show_encryption_tool():
    st.header("Encryption / Decryption Tool")
    txt = st.text_area("Text to encrypt")
    if st.button("Encrypt"):
        if not txt.strip():
            st.warning("Please enter text.")
        else:
            token = encrypt_data(sanitize_text(txt))
            st.code(token.decode("utf-8"))
    token_in = st.text_area("Ciphertext to decrypt")
    if st.button("Decrypt"):
        try:
            if not token_in.strip():
                st.warning("Please enter ciphertext.")
            else:
                plain = decrypt_data(token_in.encode("utf-8"))
                st.code(plain)
        except Exception:
            st.error("Invalid or corrupted token.")

def show_audit_logs():
    st.header("Activity Logs")
    uid = st.session_state["user_id"]
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, user_id, action, details, timestamp FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 200",
        (uid,),
    )
    rows = c.fetchall()
    conn.close()

    if not rows:
        st.info("No logs found.")
        return

    # Convert to DataFrame for display and download
    df = pd.DataFrame(rows, columns=["ID", "User ID", "Action", "Details", "Timestamp"])
    st.dataframe(df, use_container_width=True)

    # Convert to Excel
    buffer = BytesIO()
    df.to_excel(buffer, index=False, sheet_name="AuditLogs")
    buffer.seek(0)

    st.download_button(
        "⬇️ Download Audit Logs (Excel)",
        data=buffer,
        file_name="audit_logs.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

    st.caption("Logs include recent actions such as login, registration, wallet creation, etc.")


def export_testcases_excel():
    st.header("Export Manual Testcases Template")
    tests = [{"No.": i, "Test Case": f"Security Test {i}", "Action Performed": "", "Expected Outcome": "", "Observed Result": "", "Pass/Fail": ""} for i in range(1, 26)]
    df = pd.DataFrame(tests)
    bio = BytesIO()
    df.to_excel(bio, index=False, sheet_name="testcases")
    bio.seek(0)
    st.download_button("Download testcases.xlsx", data=bio, file_name="manual_testcases.xlsx")

# ---------------------------
# Main
# ---------------------------
def main():
    inject_css()
    init_db()
    init_crypto()

    st.sidebar.markdown("<div class='neon-card'><h3 class='neon-accent'>Secure FinTech</h3></div>", unsafe_allow_html=True)
    if "user_id" not in st.session_state:
        st.session_state["user_id"] = None
        st.session_state["username"] = None

    page = st.sidebar.selectbox("Navigation", ["Home", "Register", "Login", "Profile", "Wallets", "File Upload", "Encryption Tool", "Audit Logs", "Export Testcases"])
    if st.sidebar.button("Logout"):
        try:
            log_action(st.session_state.get("user_id"), "logout", "User logged out")
        except:
            pass
    st.session_state.clear()
    st.success("You have been logged out successfully.")
    st.experimental_rerun()

    try:
        if page == "Home": show_home()
        elif page == "Register": show_register()
        elif page == "Login": show_login()
        elif page == "Profile":
            if require_login(): show_profile()
            else: st.warning("Login first.")
        elif page == "Wallets":
            if require_login(): show_wallets()
            else: st.warning("Login first.")
        elif page == "File Upload":
            if require_login(): show_file_upload()
            else: st.warning("Login first.")
        elif page == "Encryption Tool":
            if require_login(): show_encryption_tool()
            else: st.warning("Login first.")
        elif page == "Audit Logs":
            if require_login(): show_audit_logs()
            else: st.warning("Login first.")
        elif page == "Export Testcases":
            export_testcases_excel()
    except Exception:
        st.error("An unexpected error occurred.")
        log_action(st.session_state.get("user_id"), "error_generic", "App crashed safely")

if __name__ == "__main__":
    main()
