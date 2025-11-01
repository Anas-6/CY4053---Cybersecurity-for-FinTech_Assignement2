"""
streamlit_app.py
Secure FinTech mini-app for CY4053 Assignment 2
Features:
 - User registration & login (bcrypt hashed passwords)
 - Password strength enforcement
 - Input validation / sanitization
 - Session management using st.session_state
 - Secure data storage using SQLite + Fernet encryption for wallet data
 - Error handling with generic messages
 - Activity / audit logs
 - Profile update, password change
 - Wallet create/view (encrypt/decrypt)
 - File upload validation (allowed types)
 - Export a prefilled manual testcases Excel for documentation
 - Dark cyber/neon UI via injected CSS
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
KEY_PATH = "secret.key"  # symmetric key for encrypting wallet data
ALLOWED_UPLOAD_TYPES = ["png", "jpg", "jpeg", "pdf", "csv", "txt"]  # for file upload validation

# ---------------------------
# Helper: UI theme/CSS (dark neon)
# ---------------------------
def inject_css():
    st.markdown(
        """
        <style>
        /* Background gradient */
        .stApp {
            background: radial-gradient(circle at 10% 10%, #041628 0%, #071428 25%, #02040a 100%);
            color: #cfefff;
            font-family: "Inter", sans-serif;
        }
        /* Neon card */
        .neon-card {
            background: rgba(10, 20, 30, 0.55);
            border-radius: 12px;
            padding: 18px;
            box-shadow: 0 0 20px rgba(0,255,200,0.04), 0 0 6px rgba(0,255,200,0.06) inset;
            border: 1px solid rgba(0,255,200,0.08);
        }
        /* Buttons */
        .stButton>button {
            background: linear-gradient(90deg,#00fff0,#00a3ff);
            color: #001217;
            font-weight: 600;
            border-radius: 8px;
            padding: 8px 14px;
            box-shadow: 0 2px 10px rgba(0,160,255,0.15);
        }
        /* Inputs */
        .stTextInput>div>div>input, .stTextArea>div>div>textarea {
            background: rgba(255,255,255,0.03);
            color: #dff7ff;
            border-radius: 6px;
            padding: 8px;
        }
        /* Headings */
        h1, h2, h3 {
            color: #bff7ff;
            text-shadow: 0 0 6px rgba(0,255,220,0.06);
        }
        /* small neon accent */
        .neon-accent { color: #86fff2; font-weight:700; }
        </style>
        """,
        unsafe_allow_html=True,
    )

# ---------------------------
# KEY / DB init
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
    # Users table: id, username (unique), email, password_hash, created_at
    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        created_at TEXT NOT NULL
    )
    """)
    # Wallets: id, owner_id, wallet_name, encrypted_data, created_at
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
    # Audit logs: id, user_id (nullable), action, details, timestamp
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
def hash_password(plain_password: str) -> bytes:
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())

def verify_password(plain_password: str, password_hash: bytes) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), password_hash)
    except Exception:
        return False

# Password strength rule
PASSWORD_REGEX = re.compile(
    r"^(?=.{8,})(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).*$"
)
def is_strong_password(pw: str) -> bool:
    return bool(PASSWORD_REGEX.match(pw))

# Basic email validation
EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
def is_valid_email(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

# Input sanitization (very basic — for examples)
def sanitize_text(s: str) -> str:
    # strip leading/trailing, limit length, remove suspicious tags
    s = s.strip()
    if len(s) > 2000:
        s = s[:2000]
    # remove script tags
    s = re.sub(r"(?i)<\s*script.*?>.*?<\s*/\s*script\s*>", "", s, flags=re.DOTALL)
    return s

# ---------------------------
# Audit logging
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
        # swallow logging errors to avoid info leakage to user
        pass

# ---------------------------
# User operations
# ---------------------------
def register_user(username, email, password):
    username = sanitize_text(username)
    email = sanitize_text(email)
    if not is_valid_email(email):
        return False, "Invalid email"
    if not is_strong_password(password):
        return False, "Password does not meet strength requirements"
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
        return True, "Registered"
    except sqlite3.IntegrityError as e:
        msg = "Username or email already exists"
        return False, msg
    except Exception:
        return False, "Registration failed"

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
        return False, "Invalid email"
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
        conn.commit()
        conn.close()
        log_action(user_id, "profile_update", "email_changed")
        return True, "Email updated"
    except sqlite3.IntegrityError:
        return False, "Email already in use"
    except Exception:
        return False, "Update failed"

def change_user_password(user_id, old_password, new_password):
    if not is_strong_password(new_password):
        return False, "New password not strong enough"
    user = get_user_by_id(user_id)
    if user is None:
        return False, "User not found"
    if not verify_password(old_password, user["password_hash"]):
        return False, "Old password incorrect"
    try:
        new_hash = hash_password(new_password)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user_id))
        conn.commit()
        conn.close()
        log_action(user_id, "password_change", "user_changed_password")
        return True, "Password changed"
    except Exception:
        return False, "Password update failed"

# ---------------------------
# Wallet encryption helpers
# ---------------------------
fernet = None
def init_crypto():
    global fernet
    key = load_or_create_key()
    fernet = Fernet(key)

def encrypt_data(plain_text: str) -> bytes:
    return fernet.encrypt(plain_text.encode("utf-8"))

def decrypt_data(token: bytes) -> str:
    return fernet.decrypt(token).decode("utf-8")

def create_wallet(owner_id, wallet_name, wallet_data_plain):
    try:
        enc = encrypt_data(wallet_data_plain)
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO wallets (owner_id, wallet_name, encrypted_data, created_at) VALUES (?, ?, ?, ?)",
                  (owner_id, wallet_name, enc, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        log_action(owner_id, "create_wallet", f"wallet:{wallet_name}")
        return True, "Wallet created"
    except Exception:
        return False, "Wallet creation failed"

def get_wallets_for_user(owner_id):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, wallet_name, encrypted_data, created_at FROM wallets WHERE owner_id = ?", (owner_id,))
    rows = c.fetchall()
    conn.close()
    return rows

# ---------------------------
# File upload validation
# ---------------------------
def validate_uploaded_file(uploaded_file):
    # Accept only allowed extensions and small sizes
    filename = uploaded_file.name
    ext = filename.split(".")[-1].lower()
    if ext not in ALLOWED_UPLOAD_TYPES:
        return False, f"File type .{ext} not allowed"
    if uploaded_file.size > 5 * 1024 * 1024:  # 5 MB limit
        return False, "File too large (>5MB)"
    return True, "OK"

# ---------------------------
# UI Pages
# ---------------------------
def show_home():
    st.title("🔐 Secure FinTech Mini App — Cyber Edition")
    st.markdown("Welcome — this app was built to demonstrate secure coding and manual testing scenarios for your CY4053 assignment.")
    st.divider()

def show_register():
    st.header("Create Account")
    with st.form("register_form", clear_on_submit=False):
        username = st.text_input("Username", max_chars=150)
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        confirm = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register")
        if submitted:
            try:
                if password != confirm:
                    st.warning("Passwords do not match")
                else:
                    ok, msg = register_user(username, email, password)
                    if ok:
                        st.success("Registered successfully. Please login.")
                    else:
                        st.error(msg)
            except Exception:
                st.error("Registration error")

def show_login():
    st.header("Login")
    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")
        if submitted:
            try:
                user = get_user_by_username(username)
                if user and verify_password(password, user["password_hash"]):
                    st.session_state["user_id"] = user["id"]
                    st.session_state["username"] = user["username"]
                    st.success("Login successful")
                    log_action(user["id"], "login", "User logged in")
                else:
                    st.error("Invalid credentials")
                    # log failed login attempt w/o revealing sensitive details
                    log_action(None, "login_failed", f"username_attempt:{sanitize_text(username)}")
            except Exception:
                st.error("Login error")

def require_login():
    return "user_id" in st.session_state and st.session_state["user_id"] is not None

def show_profile():
    st.header("Profile")
    user = get_user_by_id(st.session_state["user_id"])
    if not user:
        st.error("User not found")
        return
    st.markdown(f"**Username:** {sanitize_text(user['username'])}")
    st.markdown(f"**Email:** {sanitize_text(user['email'])}")
    st.divider()
    st.subheader("Update Email")
    with st.form("email_form"):
        new_email = st.text_input("New email")
        submitted = st.form_submit_button("Update Email")
        if submitted:
            ok, msg = update_user_email(user["id"], new_email)
            if ok:
                st.success(msg)
            else:
                st.error(msg)
    st.divider()
    st.subheader("Change Password")
    with st.form("pw_form"):
        old_pw = st.text_input("Old password", type="password")
        new_pw = st.text_input("New password", type="password")
        confirm_pw = st.text_input("Confirm new password", type="password")
        submitted_pw = st.form_submit_button("Change Password")
        if submitted_pw:
            if new_pw != confirm_pw:
                st.warning("New passwords do not match")
            else:
                ok, msg = change_user_password(user["id"], old_pw, new_pw)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

def show_wallets():
    st.header("Wallets (Encrypted Storage)")
    st.markdown("Create wallets that store sensitive data encrypted with server-side key.")
    st.divider()
    # Create wallet
    st.subheader("Create Wallet")
    with st.form("create_wallet_form"):
        wallet_name = st.text_input("Wallet name")
        wallet_data = st.text_area("Private data (e.g., private key or secret)", help="Sensitive data will be encrypted in storage")
        submitted = st.form_submit_button("Create Wallet")
        if submitted:
            if not wallet_name or not wallet_data:
                st.error("Provide wallet name and data")
            else:
                ok, msg = create_wallet(st.session_state["user_id"], sanitize_text(wallet_name), sanitize_text(wallet_data))
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
    st.divider()
    # List wallets
    st.subheader("Your Wallets")
    rows = get_wallets_for_user(st.session_state["user_id"])
    if not rows:
        st.info("No wallets created yet")
    else:
        for r in rows:
            st.markdown(f"**{sanitize_text(r['wallet_name'])}** — created: {r['created_at']}")
            col1, col2 = st.columns([1,3])
            with col1:
                if st.button("Decrypt", key=f"dec_{r['id']}"):
                    try:
                        plain = decrypt_data(r["encrypted_data"])
                        st.text_area("Decrypted data (sensitive)", value=plain, height=120)
                        log_action(st.session_state["user_id"], "wallet_decrypt", f"wallet:{r['id']}")
                    except Exception:
                        st.error("Decryption failed")
            with col2:
                if st.button("Show metadata", key=f"meta_{r['id']}"):
                    st.write({"wallet_id": r["id"], "created_at": r["created_at"]})
    st.divider()

def show_encryption_tool():
    st.header("Encryption / Decryption Tool (Developer Aid)")
    st.markdown("Use this to test encryption/decryption. This replicates what the app does for wallet data.")
    text = st.text_area("Plain text to encrypt")
    if st.button("Encrypt"):
        if text.strip() == "":
            st.warning("Provide some text")
        else:
            token = encrypt_data(sanitize_text(text))
            st.code(token.decode("utf-8"))
    token_input = st.text_area("Token to decrypt")
    if st.button("Decrypt"):
        try:
            if token_input.strip() == "":
                st.warning("Provide a token")
            else:
                # accept bytes or string
                if isinstance(token_input, str):
                    tok = token_input.encode("utf-8")
                else:
                    tok = token_input
                plain = decrypt_data(tok)
                st.code(plain)
        except Exception:
            st.error("Decryption failed (invalid token)")

def show_audit_logs():
    st.header("Activity / Audit Logs")
    st.markdown("Only admins or user (owner) can view their logs here. Logs do not expose sensitive content.")
    uid = st.session_state["user_id"]
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, user_id, action, details, timestamp FROM audit_logs WHERE user_id = ? OR user_id IS NULL ORDER BY timestamp DESC LIMIT 200", (uid,))
    rows = c.fetchall()
    conn.close()
    if not rows:
        st.info("No logs found")
    else:
        for r in rows:
            sid = r["user_id"] if r["user_id"] else "system"
            st.markdown(f"- **{r['timestamp']}** — `{sid}` — *{r['action']}* — {sanitize_text(r['details'] or '')}")

def show_file_upload():
    st.header("Secure File Upload (Validated)")
    uploaded = st.file_uploader("Upload file (png/jpg/pdf/txt/csv)", type=ALLOWED_UPLOAD_TYPES)
    if uploaded:
        ok, msg = validate_uploaded_file(uploaded)
        if not ok:
            st.error(msg)
        else:
            st.success("File accepted")
            # show basic info without storing to disk (to avoid leaking data)
            st.write({"filename": uploaded.name, "size": uploaded.size})
            # Optionally allow user to download back
            st.download_button("Download file (safe)", data=uploaded.getvalue(), file_name=uploaded.name)

def export_testcases_excel():
    st.header("Export: Manual Testcases Template (20+ tests)")
    st.markdown("Click to generate an Excel with 20+ suggested manual tests. You can edit and add screenshots for submission.")
    # build a sample dataframe of 20 tests (based on assignment)
    tests = [
        {"No.":1,"Test Case":"SQL injection in login","Action Performed":"Entered ' OR 1=1 -- in username","Expected Outcome":"Rejected / generic error","Observed Result":"","Pass/Fail":""},
        {"No.":2,"Test Case":"Weak password allowed?","Action Performed":"Register with 12345","Expected Outcome":"Rejected / warn","Observed Result":"","Pass/Fail":""},
        {"No.":3,"Test Case":"XSS in username","Action Performed":"<script>alert(1)</script>","Expected Outcome":"Sanitized / no alert","Observed Result":"","Pass/Fail":""},
        {"No.":4,"Test Case":"Access dashboard without login","Action Performed":"Open dashboard URL directly","Expected Outcome":"Redirect to login","Observed Result":"","Pass/Fail":""},
        {"No.":5,"Test Case":"Session expiry","Action Performed":"Idle for 5+ minutes","Expected Outcome":"Auto logout / session cleared","Observed Result":"","Pass/Fail":""},
        {"No.":6,"Test Case":"Logout invalidation","Action Performed":"Login then logout then press back","Expected Outcome":"No access, redirected","Observed Result":"","Pass/Fail":""},
        {"No.":7,"Test Case":"Database file inspect","Action Performed":"Open DB file","Expected Outcome":"Passwords hashed","Observed Result":"","Pass/Fail":""},
        {"No.":8,"Test Case":"File upload validation","Action Performed":"Upload .exe file","Expected Outcome":"Rejected","Observed Result":"","Pass/Fail":""},
        {"No.":9,"Test Case":"Error message leakage","Action Performed":"Cause invalid query","Expected Outcome":"Generic error","Observed Result":"","Pass/Fail":""},
        {"No.":10,"Test Case":"Input length handling","Action Performed":"Paste 5000 chars","Expected Outcome":"Validation / trimmed","Observed Result":"","Pass/Fail":""},
        {"No.":11,"Test Case":"Duplicate registration","Action Performed":"Register existing username","Expected Outcome":"Error shown","Observed Result":"","Pass/Fail":""},
        {"No.":12,"Test Case":"Numeric field validation","Action Performed":"Enter letters in amount field","Expected Outcome":"Rejected","Observed Result":"","Pass/Fail":""},
        {"No.":13,"Test Case":"Password confirm mismatch","Action Performed":"Mismatched confirm","Expected Outcome":"Registration blocked","Observed Result":"","Pass/Fail":""},
        {"No.":14,"Test Case":"Unauthorized data modification","Action Performed":"Attempt change transaction ID","Expected Outcome":"Rejected","Observed Result":"","Pass/Fail":""},
        {"No.":15,"Test Case":"Email validation","Action Performed":"Enter abc@","Expected Outcome":"Reject","Observed Result":"","Pass/Fail":""},
        {"No.":16,"Test Case":"Login lockout","Action Performed":"5 failed logins","Expected Outcome":"Lockout or delay","Observed Result":"","Pass/Fail":""},
        {"No.":17,"Test Case":"Controlled error handling","Action Performed":"Force divide by zero","Expected Outcome":"Friendly error","Observed Result":"","Pass/Fail":""},
        {"No.":18,"Test Case":"Encrypted record check","Action Performed":"View wallet DB","Expected Outcome":"Encrypted field unreadable","Observed Result":"","Pass/Fail":""},
        {"No.":19,"Test Case":"Unicode input","Action Performed":"Use emoji input","Expected Outcome":"Handled gracefully","Observed Result":"","Pass/Fail":""},
        {"No.":20,"Test Case":"Empty field submission","Action Performed":"Leave required blank","Expected Outcome":"Warning displayed","Observed Result":"","Pass/Fail":""},
    ]
    df = pd.DataFrame(tests)
    towrite = BytesIO()
    df.to_excel(towrite, index=False, sheet_name="testcases")
    towrite.seek(0)
    st.download_button("Download testcases.xlsx", data=towrite, file_name="manual_testcases.xlsx")
    st.info("Edit, add screenshots and save as Word/Excel for submission.")

# ---------------------------
# App layout / router
# ---------------------------
def main():
    inject_css()
    init_db()
    init_crypto()

    st.sidebar.markdown("<div class='neon-card'><h3 class='neon-accent'>Secure FinTech</h3></div>", unsafe_allow_html=True)
    if "user_id" not in st.session_state:
        st.session_state["user_id"] = None
        st.session_state["username"] = None

    page = st.sidebar.selectbox("Navigation", ["Home", "Register", "Login", "Profile", "Wallets", "Encryption Tool", "File Upload", "Audit Logs", "Export Testcases", "Help"])
    st.sidebar.write("---")
    if require_login():
        st.sidebar.markdown(f"Logged in as **{sanitize_text(st.session_state['username'])}**")
        if st.sidebar.button("Logout"):
            log_action(st.session_state["user_id"], "logout", "User logged out")
            st.session_state["user_id"] = None
            st.session_state["username"] = None
            st.experimental_rerun()

    # route
    try:
        if page == "Home":
            show_home()
        elif page == "Register":
            show_register()
        elif page == "Login":
            if require_login():
                st.info("Already logged in")
            else:
                show_login()
        elif page == "Profile":
            if require_login():
                show_profile()
            else:
                st.warning("Please login first")
        elif page == "Wallets":
            if require_login():
                show_wallets()
            else:
                st.warning("Please login first")
        elif page == "Encryption Tool":
            if require_login():
                show_encryption_tool()
            else:
                st.warning("Please login first")
        elif page == "File Upload":
            if require_login():
                show_file_upload()
            else:
                st.warning("Please login first")
        elif page == "Audit Logs":
            if require_login():
                show_audit_logs()
            else:
                st.warning("Please login first")
        elif page == "Export Testcases":
            export_testcases_excel()
        else:
            st.write("Help")
            st.markdown("""
            **How to use**
            1. Register with a strong password (min 8 chars, upper+lower+digit+symbol).
            2. Login and create wallets to store encrypted data.
            3. Use Export Testcases to download a template for manual testing documentation.
            """)
    except Exception:
        # Generic error message to avoid leaking stack traces
        st.error("An unexpected error occurred. Please try again or contact the instructor.")
        log_action(st.session_state.get("user_id"), "error_generic", "An unexpected error occurred in main UI")

if __name__ == "__main__":
    main()
