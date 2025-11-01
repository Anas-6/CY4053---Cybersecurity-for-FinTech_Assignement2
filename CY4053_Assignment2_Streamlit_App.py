# CY4053 Assignment 2 - Secure FinTech Mini App (Streamlit)
# Name: Muhammad Anas
# Roll No: 22i-9808
# Instructor: Dr. Usama Arshad
# Course: CY4053 - Cybersecurity for FinTech
# Semester: BSFT – 7th (Fall 2025)

import streamlit as st
import sqlite3
import bcrypt
import os
import base64
from cryptography.fernet import Fernet
from datetime import datetime, timedelta
import pandas as pd
import pathlib

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
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash BLOB NOT NULL,
                    email BLOB,
                    created_at TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS profiles (
                    user_id INTEGER PRIMARY KEY,
                    full_name BLOB,
                    phone BLOB,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    amount REAL,
                    description TEXT,
                    created_at TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )''')
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
    if not plaintext:
        return None
    return FERNET.encrypt(plaintext.encode())

def decrypt_text(cipher: bytes) -> str:
    if not cipher:
        return ''
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
        audit_log(st.session_state['user']['id'], 'session_expired')
        logout_session()
        return False
    st.session_state['last_active'] = datetime.utcnow()
    return True

# --------------------------- Core App Logic ----------------------------------

def password_policy_ok(password: str) -> (bool, str):
    if len(password) < 8:
        return False, 'Password must be at least 8 characters.'
    if not any(c.isdigit() for c in password):
        return False, 'Password must include at least one digit.'
    if not any(c.isupper() for c in password):
        return False, 'Password must include at least one uppercase letter.'
    symbols = set('!@#$%^&*()-_=+[]{}|;:",.<>?/~`')
    if not any(c in symbols for c in password):
        return False, 'Password must include at least one symbol.'
    return True, 'OK'

def register_user(username, password, confirm_password, email):
    ok, msg = password_policy_ok(password)
    if not ok:
        return False, msg
    if password != confirm_password:
        return False, 'Passwords do not match.'
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

def login_user(username, password):
    row = conn.execute('SELECT id, username, password_hash FROM users WHERE username=?', (username,)).fetchone()
    if not row:
        return False, 'Invalid username or password.'
    user_id, uname, pw_hash = row
    if not check_password(password, pw_hash):
        audit_log(user_id, 'login_failed')
        return False, 'Invalid username or password.'
    create_session(row)
    return True, 'Login successful.'

def update_profile(user_id, full_name, phone, email):
    encrypted_name = encrypt_text(full_name) if full_name else None
    encrypted_phone = encrypt_text(phone) if phone else None
    encrypted_email = encrypt_text(email) if email else None
    cur = conn.execute('SELECT user_id FROM profiles WHERE user_id=?', (user_id,)).fetchone()
    if cur:
        conn.execute('UPDATE profiles SET full_name=?, phone=? WHERE user_id=?',
                     (encrypted_name, encrypted_phone, user_id))
    else:
        conn.execute('INSERT INTO profiles (user_id, full_name, phone) VALUES (?, ?, ?)',
                     (user_id, encrypted_name, encrypted_phone))
    if email:
        conn.execute('UPDATE users SET email=? WHERE id=?', (encrypted_email, user_id))
    conn.commit()
    audit_log(user_id, 'profile_update')

def create_transaction(user_id, amount, description):
    ts = datetime.utcnow().isoformat()
    conn.execute('INSERT INTO transactions (user_id, amount, description, created_at) VALUES (?, ?, ?, ?)',
                 (user_id, amount, description, ts))
    conn.commit()
    audit_log(user_id, 'create_transaction', f'amount={amount}')

def export_audit_csv():
    df = pd.read_sql_query('SELECT * FROM audit_logs', conn)
    return df.to_csv(index=False).encode()

# File validation
ALLOWED_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg'}
MAX_FILE_BYTES = 2 * 1024 * 1024

def allowed_file(filename, file_bytes):
    ext = pathlib.Path(filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        return False, 'File type not allowed.'
    if len(file_bytes) > MAX_FILE_BYTES:
        return False, 'File too large.'
    return True, 'OK'

# --------------------------- Streamlit UI -----------------------------------
st.set_page_config(page_title='Secure FinTech Mini App', layout='centered')
st.title('CY4053 — Secure FinTech Mini App')
st.write('A Streamlit app implementing secure features for manual cybersecurity testing.')

menu = st.sidebar.selectbox('Menu', ['Home', 'Register', 'Login', 'Manual Tests', 'About'])

if menu == 'Home':
    st.header('Welcome')
    st.write('Register, Login, and test security features like authentication, encryption, and validation.')

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
        st.success(msg) if ok else st.error(msg)

# Login page
if menu == 'Login':
    st.header('Login')
    with st.form('login_form'):
        username = st.text_input('Username')
        password = st.text_input('Password', type='password')
        submitted = st.form_submit_button('Login')
    if submitted:
        ok, msg = login_user(username.strip(), password)
        st.success(msg) if ok else st.error(msg)
        if ok:
            st.rerun()

# Manual Tests / Dashboard
if menu == 'Manual Tests':
    st.header('Manual Tests & Dashboard')
    if not session_is_active():
        st.warning('You must be logged in to access this area.')
    else:
        user = st.session_state['user']
        st.subheader(f'Welcome, {user["username"]}')
        st.button('Logout', on_click=logout_session)

        col1, col2 = st.columns(2)
        with col1:
            st.subheader('Create Transaction')
            with st.form('txn_form'):
                amt = st.text_input('Amount')
                desc = st.text_area('Description')
                submit_txn = st.form_submit_button('Create')
            if submit_txn:
                try:
                    amt_val = float(amt)
                    create_transaction(user['id'], amt_val, desc)
                    st.success('Transaction created.')
                except Exception:
                    st.error('Invalid amount — numeric value required.')

        with col2:
            st.subheader('Profile')
            profile_row = conn.execute('SELECT full_name, phone FROM profiles WHERE user_id=?',
                                       (user['id'],)).fetchone()
            existing_name = decrypt_text(profile_row[0]) if profile_row else ''
            existing_phone = decrypt_text(profile_row[1]) if profile_row else ''
            with st.form('profile_form'):
                full_name = st.text_input('Full name', value=existing_name)
                phone = st.text_input('Phone', value=existing_phone)
                email = st.text_input('Email',
                    value=decrypt_text(conn.execute('SELECT email FROM users WHERE id=?',
                                                    (user['id'],)).fetchone()[0]))
                save_profile = st.form_submit_button('Save Profile')
            if save_profile:
                if not full_name.strip():
                    st.error('Full name required.')
                else:
                    update_profile(user['id'], full_name.strip(), phone.strip(), email.strip())
                    st.success('Profile updated.')

        st.markdown('---')
        st.subheader('Encryption / Decryption Demonstration')
        with st.form('enc_form'):
            plain = st.text_input('Enter text to encrypt/decrypt')
            enc_submit = st.form_submit_button('Encrypt & Decrypt')
        if enc_submit:
            encrypted = encrypt_text(plain)
            decrypted = decrypt_text(encrypted)
            st.write('**Encrypted (stored form):**', encrypted)
            st.write('**Decrypted (original text):**', decrypted)
            audit_log(user['id'], 'encryption_demo', 'Performed encryption demo')

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
                os.makedirs('uploads', exist_ok=True)
                safe_name = f'uploads/{user["id"]}_{os.path.basename(uploaded.name)}'
                with open(safe_name, 'wb') as f:
                    f.write(data)
                st.success('File uploaded successfully.')
                audit_log(user['id'], 'upload', f'name={uploaded.name}')

        st.markdown('---')
        st.subheader('Your Transactions')
        txns = pd.read_sql_query(
            'SELECT id, amount, description, created_at FROM transactions WHERE user_id=? ORDER BY created_at DESC',
            conn, params=(user['id'],))
        st.dataframe(txns)

        st.markdown('---')
        st.subheader('Audit Logs')
        logs = pd.read_sql_query(
            'SELECT id, action, details, timestamp FROM audit_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 50',
            conn, params=(user['id'],))
        st.dataframe(logs)

        st.markdown('---')
        st.download_button('Export Audit Logs CSV', data=export_audit_csv(),
                           file_name='audit_logs.csv', mime='text/csv')

if menu == 'About':
    st.header('About & README')
    st.markdown('''
    **This app implements all required secure FinTech features:**
    - Hashed passwords (bcrypt)
    - Strong password validation
    - Input validation & error handling
    - Session timeout (5 min)
    - SQLite + Fernet encryption
    - Audit logs for all actions
    - File upload validation
    - Profile update with encryption
    - Encryption/decryption demo for manual testing
    ''')

# --------------------------- End of App -------------------------------------
