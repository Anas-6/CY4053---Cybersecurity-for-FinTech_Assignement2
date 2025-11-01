"""
streamlit_app.py
Secure FinTech mini-app for CY4053 Assignment 2
Final Hardened Version — by Anas (i229808)
"""

import random, string, os, re, time, bcrypt, sqlite3, pandas as pd
from datetime import datetime
from io import BytesIO
from cryptography.fernet import Fernet
import streamlit as st

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
    st.markdown("""
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
        h1, h2, h3 { color: #bff7ff; text-shadow: 0 0 6px rgba(0,255,220,0.06); }
        .neon-accent { color: #86fff2; font-weight:700; }
        </style>
    """, unsafe_allow_html=True)

# ---------------------------
# Key / DB setup
# ---------------------------
def load_or_create_key():
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f: return f.read()
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f: f.write(key)
    return key

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash BLOB NOT NULL,
        created_at TEXT NOT NULL
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS wallets(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        owner_id INTEGER NOT NULL,
        wallet_name TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT NOT NULL,
        details TEXT,
        timestamp TEXT NOT NULL
    )""")
    c.execute("""
    CREATE TABLE IF NOT EXISTS transactions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        wallet_id INTEGER NOT NULL,
        transaction_id TEXT NOT NULL,
        transaction_number TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY(wallet_id) REFERENCES wallets(id)
    )""")
    conn.commit()
    conn.close()

# ---------------------------
# Security helpers
# ---------------------------
PASSWORD_REGEX = re.compile(r"^(?=.{8,})(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).*$")
EMAIL_REGEX = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")

def hash_password(pw): return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
def verify_password(pw, hashed): 
    try: return bcrypt.checkpw(pw.encode(), hashed)
    except: return False

def is_strong_password(pw): return bool(PASSWORD_REGEX.match(pw))
def is_valid_email(email): return bool(EMAIL_REGEX.match(email))

def sanitize_text(s):
    s = s.strip()
    if len(s) > 2000:
        st.warning("⚠️ Input too long — trimmed.")
        s = s[:2000]
    s = re.sub(r"(?i)<.*?>", "", s)
    forbidden = ["'", '"', ";", "--", "/*", "*/", "=", " or ", " and ", "drop ", "delete ", "insert ", "update "]
    for token in forbidden:
        if token in s.lower():
            raise ValueError("Invalid or unsafe characters.")
    return s

# ---------------------------
# Audit Log
# ---------------------------
def log_action(uid, action, details=None):
    try:
        conn = get_db_connection(); c = conn.cursor()
        c.execute("INSERT INTO audit_logs(user_id,action,details,timestamp) VALUES(?,?,?,?)",
                  (uid, action, details, datetime.utcnow().isoformat()))
        conn.commit(); conn.close()
    except: pass

# ---------------------------
# Encryption
# ---------------------------
fernet = None
def init_crypto():
    global fernet; fernet = Fernet(load_or_create_key())
def encrypt_data(text): return fernet.encrypt(text.encode())
def decrypt_data(token): return fernet.decrypt(token).decode()

# ---------------------------
# User Operations
# ---------------------------
def register_user(username,email,password):
    try: username,email = sanitize_text(username),sanitize_text(email)
    except ValueError as e: return False,str(e)
    if not all([username,email,password]): return False,"All fields required."
    if not is_valid_email(email): return False,"Invalid email."
    if not is_strong_password(password): 
        return False,"Weak password. Use upper, lower, number, special char (min 8)."
    try:
        conn=get_db_connection();c=conn.cursor()
        pw_hash=hash_password(password)
        c.execute("INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)",
                  (username,email,pw_hash,datetime.utcnow().isoformat()))
        conn.commit();uid=c.lastrowid;conn.close()
        log_action(uid,"register",f"user:{username}")
        return True,"Registration successful."
    except sqlite3.IntegrityError: return False,"Username or email exists."
    except: return False,"Registration failed."

def get_user_by_username(u):
    try: u=sanitize_text(u)
    except: return None
    conn=get_db_connection();c=conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?",(u,))
    row=c.fetchone();conn.close();return row

def get_user_by_id(uid):
    conn=get_db_connection();c=conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?",(uid,))
    r=c.fetchone();conn.close();return r

def update_user_email(uid,new):
    if not is_valid_email(new): return False,"Invalid email."
    try:
        conn=get_db_connection();c=conn.cursor()
        c.execute("UPDATE users SET email=? WHERE id=?",(new,uid))
        conn.commit();conn.close();log_action(uid,"email_update",new)
        return True,"Email updated."
    except sqlite3.IntegrityError: return False,"Email in use."
    except: return False,"Update failed."

def change_user_password(uid,old,new):
    if not is_strong_password(new): return False,"Weak new password."
    user=get_user_by_id(uid)
    if not user or not verify_password(old,user["password_hash"]):
        return False,"Old password incorrect."
    try:
        conn=get_db_connection();c=conn.cursor()
        c.execute("UPDATE users SET password_hash=? WHERE id=?",(hash_password(new),uid))
        conn.commit();conn.close();log_action(uid,"password_change")
        return True,"Password changed."
    except: return False,"Failed."

# ---------------------------
# Wallets + Transactions
# ---------------------------
def create_wallet(uid,name,data):
    try:
        enc=encrypt_data(data)
        conn=get_db_connection();c=conn.cursor()
        c.execute("INSERT INTO wallets(owner_id,wallet_name,encrypted_data,created_at) VALUES(?,?,?,?)",
                  (uid,name,enc,datetime.utcnow().isoformat()))
        conn.commit();conn.close()
        log_action(uid,"create_wallet",name)
        return True,"Wallet created."
    except: return False,"Creation failed."

def get_wallets_for_user(uid):
    conn=get_db_connection();c=conn.cursor()
    c.execute("SELECT id,wallet_name,encrypted_data,created_at FROM wallets WHERE owner_id=?",(uid,))
    rows=c.fetchall();conn.close();return rows

def create_transaction(wallet_id,number):
    try:
        if not re.match(r"^[0-9]+$", number):
            return False,"Transaction number must be numeric."
        txid=''.join(random.choices(string.ascii_uppercase+string.digits,k=10))
        enc=encrypt_data(f"Transaction {txid}-{number}")
        conn=get_db_connection();c=conn.cursor()
        c.execute("INSERT INTO transactions(wallet_id,transaction_id,transaction_number,encrypted_data,created_at) VALUES(?,?,?,?,?)",
                  (wallet_id,txid,number,enc,datetime.utcnow().isoformat()))
        conn.commit();conn.close();log_action(None,"create_transaction",f"{txid}")
        return True,"Transaction added."
    except: return False,"Transaction failed."

def get_transactions(wallet_id):
    conn=get_db_connection();c=conn.cursor()
    c.execute("SELECT transaction_id,transaction_number,created_at FROM transactions WHERE wallet_id=?",(wallet_id,))
    r=c.fetchall();conn.close();return r

# ---------------------------
# File Upload
# ---------------------------
def validate_uploaded_file(f):
    ext=f.name.split(".")[-1].lower()
    if ext not in ALLOWED_UPLOAD_TYPES: return False,f".{ext} not allowed."
    if f.size>5*1024*1024: return False,"File >5 MB."
    return True,"OK"

# ---------------------------
# UI Pages
# ---------------------------
def show_home():
    st.title("🔐 Secure FinTech Mini-App — Cyber Edition")
    st.markdown("Secure coding demo for CY4053 Assignment 2.")
    st.divider()

def show_register():
    st.header("User Registration")
    with st.form("register_form"):
        u=st.text_input("Username"); e=st.text_input("Email")
        p=st.text_input("Password",type="password")
        c=st.text_input("Confirm Password",type="password")
        if st.form_submit_button("Register"):
            if p!=c: st.warning("Passwords do not match.")
            else:
                ok,msg=register_user(u,e,p)
                st.success(msg) if ok else st.error(msg)

def show_login():
    st.header("User Login")
    if "failed_attempts" not in st.session_state: st.session_state["failed_attempts"]=0
    if "lockout_time" not in st.session_state: st.session_state["lockout_time"]=None

    if st.session_state["lockout_time"]:
        elapsed=time.time()-st.session_state["lockout_time"]
        if elapsed<60:
            st.error(f"🚫 Locked — try again in {int(60-elapsed)} s.");return
        st.session_state["lockout_time"]=None;st.session_state["failed_attempts"]=0

    with st.form("login_form"):
        u=st.text_input("Username"); p=st.text_input("Password",type="password")
        if st.form_submit_button("Login"):
            if not u.strip() or not p.strip(): st.warning("Enter both fields.");return
            if re.search(r"('|--|;|=|\bOR\b|\bAND\b|\bDROP\b|\bSELECT\b|\bINSERT\b|\bDELETE\b)",u,re.I):
                st.error("⚠️ Unsafe input detected.");log_action(None,"login_blocked_sql",u);return
            user=get_user_by_username(u)
            if user and verify_password(p,user["password_hash"]):
                st.session_state["user_id"]=user["id"]
                st.session_state["username"]=user["username"]
                st.session_state["failed_attempts"]=0
                st.success("✅ Login successful.");log_action(user["id"],"login")
            else:
                st.session_state["failed_attempts"]+=1
                r=5-st.session_state["failed_attempts"]
                if r>0: st.error(f"Invalid credentials. {r} attempts left.")
                else:
                    st.session_state["lockout_time"]=time.time()
                    st.error("🚫 Too many attempts — locked 1 min.")
                    log_action(None,"lockout",u)

def require_login(): 
    return "user_id" in st.session_state and st.session_state["user_id"]

def show_profile():
    st.header("Profile")
    u=get_user_by_id(st.session_state["user_id"])
    if not u: st.error("User not found.");return
    st.write(f"**Username:** {u['username']}");st.write(f"**Email:** {u['email']}")
    st.divider()
    st.subheader("Update Email")
    with st.form("email_form"):
        n=st.text_input("New email")
        if st.form_submit_button("Update"):
            ok,msg=update_user_email(u["id"],n)
            st.success(msg) if ok else st.error(msg)
    st.divider()
    st.subheader("Change Password")
    with st.form("pw_form"):
        o=st.text_input("Old password",type="password")
        n=st.text_input("New password",type="password")
        c=st.text_input("Confirm new password",type="password")
        if st.form_submit_button("Change"):
            if n!=c: st.warning("Passwords don’t match.")
            else:
                ok,msg=change_user_password(u["id"],o,n)
                st.success(msg) if ok else st.error(msg)

def show_wallets():
    st.header("💼 Wallets & Transactions")
    st.caption("Add wallets and securely record encrypted transactions.")
    st.divider()

    with st.form("create_wallet"):
        name=st.text_input("Wallet Name");data=st.text_area("Private Data")
        if st.form_submit_button("Create Wallet"):
            if not name or not data: st.error("All fields required.")
            else:
                ok,msg=create_wallet(st.session_state["user_id"],sanitize_text(name),sanitize_text(data))
                st.success(msg) if ok else st.error(msg)

    st.divider()
    wallets=get_wallets_for_user(st.session_state["user_id"])
    if not wallets: st.info("No wallets yet.");return

    for w in wallets:
        st.subheader(f"💳 {w['wallet_name']} — {w['created_at']}")
        if st.button(f"Decrypt Wallet {w['id']}",key=f"d{w['id']}"):
            try: st.code(decrypt_data(w["encrypted_data"]))
            except: st.error("Decryption failed.")

        with st.form(f"txn_form_{w['id']}"):
            num=st.text_input("Transaction Number (numeric only)",key=f"n{w['id']}")
            if st.form_submit_button("Add Transaction"):
                ok,msg=create_transaction(w["id"],num)
                st.success(msg) if ok else st.error(msg)

        if st.button(f"View Transactions — {w['wallet_name']}",key=f"v{w['id']}"):
            tx=get_transactions(w["id"])
            if not tx: st.info("No transactions yet.")
            else:
                df=pd.DataFrame(tx,columns=["Transaction ID","Number","Created At"])
                st.dataframe(df,use_container_width=True)

def show_file_upload():
    st.header("Secure File Upload")
    f=st.file_uploader("Upload File",type=ALLOWED_UPLOAD_TYPES)
    if f:
        ok,msg=validate_uploaded_file(f)
        st.success("✅ File accepted.") if ok else st.error(msg)

def show_encryption_tool():
    st.header("Encryption / Decryption Tool")
    txt=st.text_area("Text to Encrypt")
    if st.button("Encrypt"):
        if not txt.strip(): st.warning("Enter text.")
        else: st.code(encrypt_data(sanitize_text(txt)).decode())
    token=st.text_area("Ciphertext to Decrypt")
    if st.button("Decrypt"):
        try:
            if not token.strip(): st.warning("Enter ciphertext.")
            else: st.code(decrypt_data(token.encode()))
        except: st.error("Invalid token.")

def show_audit_logs():
    st.header("Activity Logs")
    uid=st.session_state["user_id"]
    conn=get_db_connection();c=conn.cursor()
    c.execute("SELECT id,user_id,action,details,timestamp FROM audit_logs WHERE user_id=? ORDER BY timestamp DESC LIMIT 200",(uid,))
    rows=c.fetchall();conn.close()
    if not rows: st.info("No logs.");return
    df=pd.DataFrame(rows,columns=["ID","User ID","Action","Details","Timestamp"])
    st.dataframe(df,use_container_width=True)
    b=BytesIO();df.to_excel(b,index=False,sheet_name="Logs");b.seek(0)
    st.download_button("⬇️ Download Audit Logs (Excel)",data=b,file_name="audit_logs.xlsx")

def export_testcases_excel():
    st.header("Export Manual Testcases")
    tests=[{"No.":i,"Test Case":f"Security Test {i}","Action":"","Expected":"","Observed":"","Pass/Fail":""} for i in range(1,26)]
    df=pd.DataFrame(tests);bio=BytesIO();df.to_excel(bio,index=False,sheet_name="tests");bio.seek(0)
    st.download_button("Download manual_testcases_i229808.xlsx",data=bio,file_name="manual_testcases_i229808.xlsx")

def show_error_test():
    st.header("Secure Error-Handling Demo")
    if st.button("Force Error"):
        try: _=1/0
        except: st.error("⚠️ Controlled exception handled.");log_action(st.session_state.get("user_id"),"error_test")

# ---------------------------
# Main
# ---------------------------
def main():
    inject_css();init_db();init_crypto()

    st.sidebar.markdown("<div class='neon-card'><h3 class='neon-accent'>Secure FinTech — by Anas (i229808)</h3></div>",unsafe_allow_html=True)
    if "user_id" not in st.session_state: st.session_state["user_id"]=None
    if "username" not in st.session_state: st.session_state["username"]=None

    page=st.sidebar.selectbox("Navigation",["Home","Register","Login","Profile","Wallets","File Upload","Encryption Tool","Audit Logs","Export Testcases","Error Test"])

    if require_login():
        st.sidebar.markdown(f"**Logged in:** {st.session_state['username']}")
        if st.sidebar.button("Logout"):
            try: log_action(st.session_state.get("user_id"),"logout","User logged out")
            except: pass
            placeholder=st.empty();placeholder.success("👋 You have been logged out successfully.")
            time.sleep(1.2);st.session_state.clear();st.rerun()

    try:
        if page=="Home": show_home()
        elif page=="Register": show_register()
        elif page=="Login": show_login()
        elif page=="Profile":
            if require_login(): show_profile()
            else: st.warning("Login first.")
        elif page=="Wallets":
            if require_login(): show_wallets()
            else: st.warning("Login first.")
        elif page=="File Upload":
            if require_login(): show_file_upload()
            else: st.warning("Login first.")
        elif page=="Encryption Tool":
            if require_login(): show_encryption_tool()
            else: st.warning("Login first.")
        elif page=="Audit Logs":
            if require_login(): show_audit_logs()
            else: st.warning("Login first.")
        elif page=="Export Testcases": export_testcases_excel()
        elif page=="Error Test": show_error_test()
    except:
        st.error("Unexpected error.");log_action(st.session_state.get("user_id"),"error_generic","App crashed safely")

if __name__=="__main__":
    main()
