# CY4053 Assignment 2 - Secure FinTech Mini App (Streamlit)
# Name: Muhammad Anas
# Roll No: 22i-9808


import streamlit as st
import sqlite3
import bcrypt
import os
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import pandas as pd
from io import BytesIO

# --------------------------- Helper / Security Utilities ---------------------
DB_PATH = 'app_data.db'
KEY_FILE = 'secret.key'
SESSION_TIMEOUT_SECONDS = 300  # 5 minutes

# Generate or load symmetric key for encrypting sensitive fields
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key

FERNET_KEY = load_or_create_key()
FERNET = Fernet(FERNET_KEY)

# Database initialization
def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    c = conn.cursor()
    # users: id, username, password_hash, email (encrypted), created_at
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash BLOB NOT NULL,
                    email BLOB,
                    created_at TEXT
                )''')
    # profile: user_id, full_name (encrypted), phone (encrypted)
    c.execute('''CREATE TABLE IF NOT EXISTS profiles (
                    user_id INTEGER PRIMARY KEY,
                    full_name BLOB,
                    phone BLOB,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    # transactions: simple ledger for demo
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    amount REAL,
                    description TEXT,
                    created_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    # audit logs
    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT,
                    details TEXT,
                    timestamp TEXT
                )''')
    conn.commit()
    return conn

conn = init_db()

# Logging helper
def audit_log(user_id, action, details=''):
    ts = datetime.utcnow().isoformat()
    conn.execute('INSERT INTO audit_logs (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)',
                 (user_id, action, details, ts))
    conn.commit()

# Encryption helpers
def encrypt_text(plaintext: str) -> bytes:
    if plaintext is None:
        return None
    return FERNET.encrypt(plaintext.encode())

def decrypt_text(cipher: bytes) -> str:
    if cipher is None:
        return None
    try:
        return FERNET.decrypt(cipher).decode()
    except Exception:
        return '[decryption-error]'

# Password helpers
def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt)

def check_password(password: str, pw_hash: bytes) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), pw_hash)
    except Exception:
        return False

# --------------------------- Session Management ------------------------------
# Using st.session_state to store session details
if 'user' not in st.session_state:
    st.session_state['user'] = None
if 'last_active' not in st.session_state:
    st.session_state['last_active'] = None


def create_session(user_row):
    st.session_state['user'] = {'id': user_row[0], 'username': user_row[1]}
    st.session_state['last_active'] = datetime.utcnow()
    audit_log(user_row[0], 'login')


def logout_session():
    if st.session_state['user']:
        audit_log(st.session_state['user']['id'], 'logout')
    st.session_state['user'] = None
    st.session_state['last_active'] = None


def session_is_active():
    if st.session_state['user'] is None:
        return False
    if st.session_state['last_active'] is None:
        return False
    if datetime.utcnow() - st.session_state['last_active'] > timedelta(seconds=SESSION_TIMEOUT_SECONDS):
        # expire
        audit_log(st.session_state['user']['id'], 'session_expired')
        logout_session()
        return False
    # refresh
    st.session_state['last_active'] = datetime.utcnow()
    return True

# --------------------------- App Functionality -------------------------------

# Password policy check
def password_policy_ok(password: str) -> (bool, str):
    # Enforce: min 8 chars, at least one digit, one symbol, one uppercase
    if len(password) < 8:
        return False, 'Password must be at least 8 characters.'
    if not any(c.isdigit() for c in password):
        return False, 'Password must include at least one digit.'
    if not any(c.isupper() for c in password):
        return False, 'Password must include at least one uppercase letter.'
    symbols = set('!@#$%^&*()-_=+[]{}|;:\",.<>?/~`')
    if not any(c in symbols for c in password):
        return False, 'Password must include at least one symbol.'
    return True, 'OK'

# Registration
def register_user(username, password, confirm_password, email):
    ok, msg = password_policy_ok(password)
    if not ok:
        return False, msg
    if password != confirm_password:
        return False, 'Passwords do not match.'
    # check duplicate
    cur = conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()
    if cur:
        return False, 'Username already exists.'
    pw_hash = hash_password(password)
    encrypted_email = encrypt_text(email) if email else None
    ts = datetime.utcnow().isoformat()
    conn.execute('INSERT INTO users (username, password_hash, email, created_at) VALUES (?, ?, ?, ?)',
                 (username, pw_hash, encrypted_email, ts))
    conn.commit()
    uid = conn.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()[0]
    audit_log(uid, 'register', f'username={username}')
    return True, 'Registered successfully.'

# Login
def login_user(username, password):
    row = conn.execute('SELECT id, username, password_hash FROM users WHERE username=?', (username,)).fetchone()
    if not row:
        return False, 'Invalid username or password.'
    user_id, uname, pw_hash = row
    if not check_password(password, pw_hash):
        # record failed login
        audit_log(user_id, 'login_failed')
        # optional account lockout logic could be added
        return False, 'Invalid username or password.'
    create_session(row)
    return True, 'Login successful.'

# Profile update
def update_profile(user_id, full_name, phone, email):
    encrypted_name = encrypt_text(full_name) if full_name else None
    encrypted_phone = encrypt_text(phone) if phone else None
    encrypted_email = encrypt_text(email) if email else None
    # upsert into profiles and users
    cur = conn.execute('SELECT user_id FROM profiles WHERE user_id=?', (user_id,)).fetchone()
    if cur:
        conn.execute('UPDATE profiles SET full_name=?, phone=? WHERE user_id=?', (encrypted_name, encrypted_phone, user_id))
    else:
        conn.execute('INSERT INTO profiles (user_id, full_name, phone) VALUES (?, ?, ?)', (user_id, encrypted_name, encrypted_phone))
    if email:
        conn.execute('UPDATE users SET email=? WHERE id=?', (encrypted_email, user_id))
    conn.commit()
    audit_log(user_id, 'profile_update')

# Create a transaction
def create_transaction(user_id, amount, description):
    ts = datetime.utcnow().isoformat()
    conn.execute('INSERT INTO transactions (user_id, amount, description, created_at) VALUES (?, ?, ?, ?)',
                 (user_id, amount, description, ts))
    conn.commit()
    audit_log(user_id, 'create_transaction', f'amount={amount}')

# Fetch user data
def get_user_row(username):
    return conn.execute('SELECT id, username, password_hash, email, created_at FROM users WHERE username=?', (username,)).fetchone()

# Export audit logs
def export_audit_csv():
    df = pd.read_sql_query('SELECT * FROM audit_logs', conn)
    return df.to_csv(index=False).encode()

# Validate uploaded file
ALLOWED_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg'}
MAX_FILE_BYTES = 2 * 1024 * 1024  # 2 MB

import pathlib

def allowed_file(filename, file_bytes):
    ext = pathlib.Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, 'File type not allowed.'
    if len(file_bytes) > MAX_FILE_BYTES:
        return False, 'File too large.'
    return True, 'OK'

# --------------------------- Manual Test Cases (20+) -------------------------
# The app includes a manual test tracker UI where the student can perform tests
# and mark observed results. The tests below match the assignment's deliverable.
MANUAL_TESTS = [
    (1, 'Input Validation – SQL Injection', "Enter \"' OR 1=1--\" in login form", 'Input rejected / error handled'),
    (2, 'Password Strength', 'Try weak password "12345" on registration', 'Rejected / warning shown'),
    (3, 'Special Character Input', 'Add <script>alert(1)</script> in username', 'Sanitized / escaped output'),
    (4, 'Unauthorized Access', 'Open dashboard without login', 'Redirected to login'),
    (5, 'Session Expiry', 'Idle for 5 minutes', 'Auto logout'),
    (6, 'Logout Functionality', 'Press logout', 'Session destroyed'),
    (7, 'Data Confidentiality', 'Open DB file and inspect passwords', 'Passwords hashed or unreadable'),
    (8, 'File Upload Validation', 'Upload .exe file', 'File rejected'),
    (9, 'Error Message Leakage', 'Cause an error (invalid input)', 'Generic error shown, no stack trace'),
    (10, 'Input Length Validation', 'Enter 5000 chars in a field', 'Validation triggered'),
    (11, 'Duplicate User Registration', 'Register existing username', 'Error displayed'),
    (12, 'Number Field Validation', 'Enter letters in amount field', 'Rejected'),
    (13, 'Password Match Check', 'Mismatched confirm password', 'Registration blocked'),
    (14, 'Data Modification Attempt', 'Try to edit transaction id manually', 'Access denied'),
    (15, 'Email Validation', 'Enter invalid email abc@', 'Validation error'),
    (16, 'Login Attempt Lockout', '5 failed logins', 'Account locked (simulated)'),
    (17, 'Secure Error Handling', 'Force divide-by-zero', 'Controlled message, app does not crash'),
    (18, 'Encrypted Record Check', 'View stored data file for sensitive fields', 'Data encrypted/unreadable'),
    (19, 'Input Encoding', 'Use Unicode emoji input', 'Handled gracefully'),
    (20, 'Empty Field Submission', 'Leave required fields blank', 'Warning displayed')
]

# --------------------------- Streamlit UI -----------------------------------
st.set_page_config(page_title='Secure FinTech Mini App', layout='centered')
st.title('CY4053 — Secure FinTech Mini App')
st.write('A Streamlit demo app that implements basic secure features for manual cybersecurity testing.')

menu = st.sidebar.selectbox('Menu', ['Home', 'Register', 'Login', 'Manual Tests', 'About'])

if menu == 'Home':
    st.header('Welcome')
    st.write('Use the sidebar to Register, Login, then access the Dashboard.')
    st.write('This demo stores data locally in `app_data.db` and uses symmetric encryption for PII and bcrypt for passwords.')

# Registration page
if menu == 'Register':
    st.header('Register New User')
    with st.form('register_form'):
        username = st.text_input('Username')
        email = st.text_input('Email (optional)')
        password = st.text_input('Password', type='password')
        confirm_password = st.text_input('Confirm password', type='password')
        submitted = st.form_submit_button('Register')
    if submitted:
        ok, msg = register_user(username.strip(), password, confirm_password, email.strip())
        if ok:
            st.success(msg)
            st.info('Now try logging in from the Login page.')
        else:
            st.error(msg)

# Login page
if menu == 'Login':
    st.header('Login')
    with st.form('login_form'):
        username = st.text_input('Username')
        password = st.text_input('Password', type='password')
        submitted = st.form_submit_button('Login')
    if submitted:
        ok, msg = login_user(username.strip(), password)
        if ok:
            st.success(msg)
            st.experimental_rerun()
        else:
            st.error(msg)

# Manual Tests and Dashboard (requires login)
if menu == 'Manual Tests':
    st.header('Manual Tests & Dashboard')
    if not session_is_active():
        st.warning('You must be logged in to access the dashboard. Please login from the Login page.')
    else:
        user = st.session_state['user']
        st.subheader(f'Dashboard — {user["username"]}')
        st.button('Logout', on_click=logout_session)

        st.markdown('### Actions')
        col1, col2 = st.columns(2)
        with col1:
            st.subheader('Create Transaction')
            with st.form('txn_form'):
                amt = st.text_input('Amount')
                desc = st.text_area('Description')
                submit_txn = st.form_submit_button('Create')
            if submit_txn:
                # validate amount
                try:
                    amt_val = float(amt)
                    create_transaction(user['id'], amt_val, desc)
                    st.success('Transaction created.')
                except Exception:
                    st.error('Invalid amount — numeric value required.')
        with col2:
            st.subheader('Profile')
            profile_row = conn.execute('SELECT full_name, phone FROM profiles WHERE user_id=?', (user['id'],)).fetchone()
            existing_name = decrypt_text(profile_row[0]) if profile_row else ''
            existing_phone = decrypt_text(profile_row[1]) if profile_row else ''
            with st.form('profile_form'):
                full_name = st.text_input('Full name', value=existing_name)
                phone = st.text_input('Phone', value=existing_phone)
                email = st.text_input('Email', value=decrypt_text(conn.execute('SELECT email FROM users WHERE id=?', (user['id'],)).fetchone()[0]))
                save_profile = st.form_submit_button('Save Profile')
            if save_profile:
                # basic validation
                if full_name.strip() == '':
                    st.error('Full name required.')
                else:
                    update_profile(user['id'], full_name.strip(), phone.strip(), email.strip())
                    st.success('Profile updated.')

        st.markdown('---')
        st.subheader('Upload Document (allowed: pdf, png, jpg, jpeg; max 2MB)')
        uploaded = st.file_uploader('Choose a file', type=['pdf', 'png', 'jpg', 'jpeg'])
        if uploaded is not None:
            data = uploaded.read()
            allowed, reason = allowed_file(uploaded.name, data)
            if not allowed:
                st.error('Upload rejected: ' + reason)
                audit_log(user['id'], 'upload_rejected', f'name={uploaded.name} reason={reason}')
            else:
                # save safely
                safe_name = f'uploads/{user["id"]}_' + os.path.basename(uploaded.name)
                os.makedirs('uploads', exist_ok=True)
                with open(safe_name, 'wb') as f:
                    f.write(data)
                st.success('File uploaded and stored safely.')
                audit_log(user['id'], 'upload', f'name={uploaded.name}')

        st.markdown('---')
        st.subheader('Your Transactions')
        txns = pd.read_sql_query('SELECT id, amount, description, created_at FROM transactions WHERE user_id=? ORDER BY created_at DESC', conn, params=(user['id'],))
        st.dataframe(txns)

        st.markdown('---')
        st.subheader('Audit Logs (your recent actions)')
        logs = pd.read_sql_query('SELECT id, action, details, timestamp FROM audit_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 50', conn, params=(user['id'],))
        st.dataframe(logs)

        st.markdown('---')
        st.subheader('Manual Test Cases (mark Observed Result)')
        test_df = pd.DataFrame(MANUAL_TESTS, columns=['No', 'Test Case', 'Action Performed', 'Expected Outcome'])
        st.table(test_df[['No', 'Test Case', 'Action Performed', 'Expected Outcome']])

        # allow user to record observed results and pass/fail
        st.markdown('#### Record Observed Results')
        selected = st.selectbox('Select test to record', test_df['No'])
        obs = st.text_area('Observed Result')
        passed = st.selectbox('Pass / Fail', ['Pass', 'Fail'])
        if st.button('Save Test Observation'):
            # store in audit_logs for traceability
            audit_log(user['id'], 'manual_test_observation', f'test_no={selected} result={passed} observed={obs[:200]}')
            st.success('Observation recorded in audit logs.')

        st.markdown('---')
        st.subheader('Export Options')
        if st.button('Export Audit Logs CSV'):
            csv_bytes = export_audit_csv()
            st.download_button('Download audit logs CSV', data=csv_bytes, file_name='audit_logs.csv')

        st.markdown('---')
        st.write('If you need to submit screenshots of each test, use the Manual Tests table above and the Save Observation button to keep a digital record in audit logs. Screenshots should be collected manually as per assignment instructions.')

if menu == 'About':
    st.header('About & README')
    st.markdown('''
    **This app implements the following security-aware features required by the assignment:**
    - User registration & login with bcrypt-hashed passwords.
    - Password strength enforcement during registration.
    - Input validation for numeric fields.
    - Session management with auto-expiry after 5 minutes of inactivity.
    - Data storage in SQLite with sensitive fields encrypted using Fernet symmetric encryption.
    - Error handling: forms validate input and show generic errors rather than stack traces.
    - File upload validation (extension + size limit).
    - Audit / activity logs recorded in a secure DB table.
    - Profile update page with validation and encryption.

    **How to run**
    1. Install dependencies: `pip install streamlit bcrypt cryptography pandas`
    2. Run: `streamlit run CY4053_Assignment2_Streamlit_App.py`

    **Deliverables you must submit (suggested)**
    - Source code (this file) + GitHub link
    - Test-case documentation table (download or recreate the table + screenshots)
    - Optional video demo link

    ### Built-in Manual Tests
    The app ships with 20 explicit manual test cases that you can perform. Use the "Manual Tests" page to run each step, take screenshots, and record observed results. The Save Observation action writes a record to the audit logs for traceability.
    ''')

# --------------------------- End of App -------------------------------------


