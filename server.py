#!/usr/bin/env python3
"""
BharatBank — Python Backend Server
Mirrors the Java banking system logic with a REST API.
Requires Python 3.6+ (no external dependencies — uses stdlib only)
"""

import sqlite3
import hashlib
import secrets
import base64
import json
import os
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from functools import wraps

DB_PATH = "bank_system.db"
PORT = 8080

# ──────────────────────────────────────────────
# SECURITY UTIL
# ──────────────────────────────────────────────

def generate_salt() -> str:
    return base64.b64encode(secrets.token_bytes(16)).decode()

def hash_password(password: str, salt: str) -> str:
    salt_bytes = base64.b64decode(salt)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_bytes, 100_000)
    return base64.b64encode(dk).decode()

def verify_password(raw: str, stored_hash: str, salt: str) -> bool:
    return hash_password(raw, salt) == stored_hash

# ──────────────────────────────────────────────
# DATABASE
# ──────────────────────────────────────────────

def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def init_db():
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS Users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            failed_login_attempts INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS Accounts (
            account_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            balance REAL DEFAULT 0.0,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE,
            UNIQUE(user_id, type)
        );
        CREATE TABLE IF NOT EXISTS Transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_account INTEGER,
            to_account INTEGER,
            type TEXT NOT NULL,
            amount REAL NOT NULL,
            charges REAL DEFAULT 0.0,
            note TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS FixedDeposits (
            fd_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            source_account_id INTEGER NOT NULL,
            principal REAL NOT NULL,
            annual_rate REAL NOT NULL,
            years INTEGER NOT NULL,
            maturity_amount REAL NOT NULL,
            status TEXT DEFAULT 'ACTIVE',
            penalty_applied INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE,
            FOREIGN KEY(source_account_id) REFERENCES Accounts(account_id)
        );
        CREATE TABLE IF NOT EXISTS Loans (
            loan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            account_id INTEGER NOT NULL,
            principal REAL NOT NULL,
            annual_rate REAL NOT NULL,
            years INTEGER NOT NULL,
            emi REAL NOT NULL,
            total_payable REAL NOT NULL,
            amount_paid REAL DEFAULT 0.0,
            status TEXT DEFAULT 'ACTIVE',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE,
            FOREIGN KEY(account_id) REFERENCES Accounts(account_id)
        );
        CREATE TABLE IF NOT EXISTS Beneficiaries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            beneficiary_account_id INTEGER NOT NULL,
            nickname TEXT,
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE,
            FOREIGN KEY(beneficiary_account_id) REFERENCES Accounts(account_id),
            UNIQUE(user_id, beneficiary_account_id)
        );
        CREATE TABLE IF NOT EXISTS Notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS Sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            user_name TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """)
        # Seed admin
        row = conn.execute("SELECT id FROM Users WHERE name = 'admin'").fetchone()
        if not row:
            salt = generate_salt()
            ph = hash_password("admin123", salt)
            conn.execute("INSERT INTO Users (id, name, password_hash, salt, role) VALUES (1,'admin',?,?,'Admin')",
                         (ph, salt))
        conn.commit()
    print(f"✅ Database initialised at {os.path.abspath(DB_PATH)}")

# ──────────────────────────────────────────────
# SESSION STORE (in-memory + DB backed)
# ──────────────────────────────────────────────

sessions = {}  # token -> {user_id, user_name, role}

def create_session(user_id, user_name, role):
    token = secrets.token_hex(32)
    sessions[token] = {"user_id": user_id, "user_name": user_name, "role": role}
    return token

def get_session(token):
    return sessions.get(token)

def delete_session(token):
    sessions.pop(token, None)

# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def add_notification(conn, user_id, message):
    try:
        conn.execute("INSERT INTO Notifications (user_id, message) VALUES (?, ?)", (user_id, message))
    except Exception:
        pass

def calc_emi(principal, annual_rate, years):
    months = years * 12
    mr = annual_rate / (12 * 100.0)
    emi = (principal * mr * (1 + mr)**months) / ((1 + mr)**months - 1)
    total = emi * months
    return round(emi, 2), round(total, 2)

# ──────────────────────────────────────────────
# API HANDLERS
# ──────────────────────────────────────────────

def ok(data=None, message="Success"):
    return {"success": True, "message": message, "data": data}

def err(message):
    return {"success": False, "message": message, "data": None}

MAX_FAILED = 5
LARGE_WITHDRAW_THRESHOLD = 10000.0
LARGE_WITHDRAW_CHARGE = 0.01
MIN_SAVINGS_BALANCE = 500.0
EARLY_FD_PENALTY = 0.01

# ---- AUTH ----

def handle_login(body):
    name = body.get("name", "").strip()
    password = body.get("password", "")
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM Users WHERE name=? AND is_active=1", (name,)).fetchone()
        if not row:
            return err("User not found.")
        if row["failed_login_attempts"] >= MAX_FAILED:
            return err("Account locked due to too many failed attempts. Contact admin.")
        if not verify_password(password, row["password_hash"], row["salt"]):
            conn.execute("UPDATE Users SET failed_login_attempts=failed_login_attempts+1 WHERE id=?", (row["id"],))
            conn.commit()
            remaining = MAX_FAILED - row["failed_login_attempts"] - 1
            return err(f"Invalid credentials. Attempts remaining: {max(0, remaining)}")
        conn.execute("UPDATE Users SET failed_login_attempts=0 WHERE id=?", (row["id"],))
        conn.commit()
        token = create_session(row["id"], row["name"], row["role"])
        return ok({"token": token, "user_id": row["id"], "user_name": row["name"], "role": row["role"]}, "Login successful")

def handle_register(body):
    name = body.get("name", "").strip()
    password = body.get("password", "")
    if not name or len(password) < 6:
        return err("Username cannot be empty and password must be at least 6 characters.")
    salt = generate_salt()
    ph = hash_password(password, salt)
    try:
        with get_conn() as conn:
            conn.execute("INSERT INTO Users (name, password_hash, salt, role) VALUES (?,?,?,'Customer')", (name, ph, salt))
            conn.commit()
        return ok(message="Registered successfully! You can now login.")
    except sqlite3.IntegrityError:
        return err("Username already taken.")

def handle_logout(session, body):
    token = body.get("token")
    delete_session(token)
    return ok(message="Logged out successfully.")

def handle_change_password(session, body):
    old_pass = body.get("old_password", "")
    new_pass = body.get("new_password", "")
    if len(new_pass) < 6:
        return err("New password must be at least 6 characters.")
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM Users WHERE id=?", (session["user_id"],)).fetchone()
        if not row or not verify_password(old_pass, row["password_hash"], row["salt"]):
            return err("Old password is incorrect.")
        new_salt = generate_salt()
        new_hash = hash_password(new_pass, new_salt)
        conn.execute("UPDATE Users SET password_hash=?, salt=? WHERE id=?", (new_hash, new_salt, session["user_id"]))
        conn.commit()
    return ok(message="Password changed successfully.")

# ---- ACCOUNTS ----

def handle_create_account(session, body):
    acc_type = body.get("type", "").strip().capitalize()
    if acc_type not in ("Savings", "Current"):
        return err("Invalid account type. Use 'Savings' or 'Current'.")
    try:
        with get_conn() as conn:
            conn.execute("INSERT INTO Accounts (user_id, type) VALUES (?,?)", (session["user_id"], acc_type))
            add_notification(conn, session["user_id"], f"New {acc_type} account opened successfully.")
            conn.commit()
        return ok(message=f"{acc_type} account created successfully.")
    except sqlite3.IntegrityError:
        return err(f"You already have a {acc_type} account.")

def handle_view_balance(session, body):
    uid = session["user_id"]
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT account_id, type, balance, created_at FROM Accounts WHERE user_id=? AND is_active=1", (uid,)
        ).fetchall()
    return ok([dict(r) for r in rows])

def user_owns_account(conn, user_id, account_id):
    r = conn.execute("SELECT 1 FROM Accounts WHERE account_id=? AND user_id=? AND is_active=1", (account_id, user_id)).fetchone()
    return r is not None

def handle_deposit(session, body):
    acc_id = int(body.get("account_id", 0))
    amount = float(body.get("amount", 0))
    if amount <= 0:
        return err("Amount must be greater than zero.")
    if amount > 1_000_000:
        return err("Single deposit limit is ₹10,00,000.")
    with get_conn() as conn:
        if not user_owns_account(conn, session["user_id"], acc_id):
            return err("Account not found or does not belong to you.")
        conn.execute("UPDATE Accounts SET balance=balance+? WHERE account_id=?", (amount, acc_id))
        conn.execute("INSERT INTO Transactions (from_account,to_account,type,amount,charges,note) VALUES (0,?,?,?,0.0,?)",
                     (acc_id, "Deposit", amount, "Cash deposit"))
        add_notification(conn, session["user_id"], f"Deposited ₹{amount:,.2f} to account #{acc_id}.")
        conn.commit()
        new_bal = conn.execute("SELECT balance FROM Accounts WHERE account_id=?", (acc_id,)).fetchone()["balance"]
    return ok({"new_balance": new_bal}, f"Deposit successful. New balance: ₹{new_bal:,.2f}")

def handle_withdraw(session, body):
    acc_id = int(body.get("account_id", 0))
    amount = float(body.get("amount", 0))
    if amount <= 0:
        return err("Amount must be greater than zero.")
    with get_conn() as conn:
        if not user_owns_account(conn, session["user_id"], acc_id):
            return err("Account not found or does not belong to you.")
        row = conn.execute("SELECT balance, type FROM Accounts WHERE account_id=?", (acc_id,)).fetchone()
        balance, acc_type = row["balance"], row["type"]
        charges = amount * LARGE_WITHDRAW_CHARGE if amount >= LARGE_WITHDRAW_THRESHOLD else 0.0
        total = amount + charges
        if acc_type == "Savings" and (balance - total) < MIN_SAVINGS_BALANCE:
            return err(f"Savings accounts must maintain a minimum balance of ₹{MIN_SAVINGS_BALANCE:,.2f}.")
        if balance < total:
            return err(f"Insufficient balance. Required: ₹{total:,.2f} | Available: ₹{balance:,.2f}")
        conn.execute("UPDATE Accounts SET balance=balance-? WHERE account_id=?", (total, acc_id))
        note = "Large withdrawal - service charge applied" if charges > 0 else "Regular withdrawal"
        conn.execute("INSERT INTO Transactions (from_account,to_account,type,amount,charges,note) VALUES (?,0,?,?,?,?)",
                     (acc_id, "Withdraw", amount, charges, note))
        add_notification(conn, session["user_id"], f"Withdrew ₹{amount:,.2f} from account #{acc_id}.")
        conn.commit()
        new_bal = conn.execute("SELECT balance FROM Accounts WHERE account_id=?", (acc_id,)).fetchone()["balance"]
    return ok({"new_balance": new_bal, "charges": charges, "total_deducted": total},
              f"Withdrawal successful. Charges: ₹{charges:,.2f}")

def handle_transfer(session, body):
    from_acc = int(body.get("from_account", 0))
    to_acc = int(body.get("to_account", 0))
    amount = float(body.get("amount", 0))
    if from_acc == to_acc:
        return err("Cannot transfer to the same account.")
    if amount <= 0:
        return err("Amount must be positive.")
    with get_conn() as conn:
        if not user_owns_account(conn, session["user_id"], from_acc):
            return err("Source account not found or does not belong to you.")
        dest = conn.execute("SELECT 1 FROM Accounts WHERE account_id=? AND is_active=1", (to_acc,)).fetchone()
        if not dest:
            return err("Destination account does not exist.")
        bal = conn.execute("SELECT balance FROM Accounts WHERE account_id=?", (from_acc,)).fetchone()["balance"]
        if bal < amount:
            return err(f"Insufficient balance. Available: ₹{bal:,.2f}")
        conn.execute("UPDATE Accounts SET balance=balance-? WHERE account_id=?", (amount, from_acc))
        conn.execute("UPDATE Accounts SET balance=balance+? WHERE account_id=?", (amount, to_acc))
        conn.execute("INSERT INTO Transactions (from_account,to_account,type,amount,charges,note) VALUES (?,?,?,?,0.0,?)",
                     (from_acc, to_acc, "Transfer", amount, "Fund transfer"))
        dest_owner = conn.execute("SELECT user_id FROM Accounts WHERE account_id=?", (to_acc,)).fetchone()["user_id"]
        if dest_owner != session["user_id"]:
            add_notification(conn, dest_owner, f"You received ₹{amount:,.2f} in account #{to_acc}.")
        add_notification(conn, session["user_id"], f"Transferred ₹{amount:,.2f} to account #{to_acc}.")
        conn.commit()
    return ok(message="Transfer successful.")

def handle_transactions(session, body):
    acc_id = int(body.get("account_id", 0))
    with get_conn() as conn:
        if not user_owns_account(conn, session["user_id"], acc_id):
            return err("Account not found or does not belong to you.")
        rows = conn.execute(
            "SELECT * FROM Transactions WHERE from_account=? OR to_account=? ORDER BY timestamp DESC LIMIT 50",
            (acc_id, acc_id)
        ).fetchall()
    return ok([dict(r) for r in rows])

# ---- FIXED DEPOSITS ----

def handle_create_fd(session, body):
    src_acc = int(body.get("source_account_id", 0))
    principal = float(body.get("principal", 0))
    rate = float(body.get("annual_rate", 0))
    years = int(body.get("years", 0))
    if principal <= 0 or rate <= 0 or years <= 0:
        return err("Invalid FD values.")
    if principal < 1000:
        return err("Minimum FD amount is ₹1,000.")
    with get_conn() as conn:
        if not user_owns_account(conn, session["user_id"], src_acc):
            return err("Account not found or does not belong to you.")
        bal = conn.execute("SELECT balance FROM Accounts WHERE account_id=?", (src_acc,)).fetchone()["balance"]
        if bal < principal:
            return err("Insufficient balance to create FD.")
        maturity = principal * (1 + rate / 100) ** years
        conn.execute("UPDATE Accounts SET balance=balance-? WHERE account_id=?", (principal, src_acc))
        conn.execute("INSERT INTO FixedDeposits (user_id,source_account_id,principal,annual_rate,years,maturity_amount) VALUES (?,?,?,?,?,?)",
                     (session["user_id"], src_acc, principal, rate, years, maturity))
        conn.execute("INSERT INTO Transactions (from_account,to_account,type,amount,charges,note) VALUES (?,0,'FD_CREATE',?,0.0,'Fixed Deposit opened')",
                     (src_acc, principal))
        add_notification(conn, session["user_id"], f"Fixed Deposit of ₹{principal:,.2f} created. Matures at ₹{maturity:,.2f}.")
        conn.commit()
    return ok({"maturity_amount": maturity, "years": years, "rate": rate},
              f"FD created! Matures at ₹{maturity:,.2f} after {years} year(s).")

def handle_view_fds(session, body):
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM FixedDeposits WHERE user_id=? ORDER BY fd_id DESC", (session["user_id"],)).fetchall()
    return ok([dict(r) for r in rows])

def handle_close_fd(session, body):
    fd_id = int(body.get("fd_id", 0))
    early = body.get("early_closure", False)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM FixedDeposits WHERE fd_id=? AND user_id=? AND status='ACTIVE'",
                           (fd_id, session["user_id"])).fetchone()
        if not row:
            return err("Active FD not found.")
        src = row["source_account_id"]
        maturity = row["maturity_amount"]
        principal = row["principal"]
        penalty = 0
        credited = maturity
        penalty_applied = False
        if early:
            penalty = principal * EARLY_FD_PENALTY
            credited = principal - penalty
            penalty_applied = True
        conn.execute("UPDATE Accounts SET balance=balance+? WHERE account_id=?", (credited, src))
        conn.execute("UPDATE FixedDeposits SET status='CLOSED', penalty_applied=? WHERE fd_id=?",
                     (1 if penalty_applied else 0, fd_id))
        tx_type = "FD_EARLY_CLOSE" if penalty_applied else "FD_CLOSE"
        note = "Early FD closure with penalty" if penalty_applied else "FD maturity credited"
        conn.execute("INSERT INTO Transactions (from_account,to_account,type,amount,charges,note) VALUES (0,?,?,?,?,?)",
                     (src, tx_type, credited, penalty, note))
        conn.commit()
    return ok({"credited": credited, "penalty": penalty}, f"FD closed. ₹{credited:,.2f} credited to account #{src}.")

# ---- LOANS ----

def handle_calc_emi(session, body):
    principal = float(body.get("principal", 0))
    rate = float(body.get("annual_rate", 0))
    years = int(body.get("years", 0))
    if principal <= 0 or rate <= 0 or years <= 0:
        return err("Invalid loan values.")
    emi, total = calc_emi(principal, rate, years)
    interest = round(total - principal, 2)
    return ok({"emi": emi, "total_payable": total, "total_interest": interest,
               "interest_ratio": round(interest / total * 100, 1)})

def handle_apply_loan(session, body):
    acc_id = int(body.get("account_id", 0))
    principal = float(body.get("principal", 0))
    rate = float(body.get("annual_rate", 0))
    years = int(body.get("years", 0))
    if principal < 5000:
        return err("Minimum loan amount is ₹5,000.")
    if principal > 5_000_000:
        return err("Maximum loan limit is ₹50,00,000.")
    with get_conn() as conn:
        if not user_owns_account(conn, session["user_id"], acc_id):
            return err("Account not found or does not belong to you.")
        active_loans = conn.execute(
            "SELECT COUNT(*) FROM Loans WHERE user_id=? AND account_id=? AND status='ACTIVE'",
            (session["user_id"], acc_id)
        ).fetchone()[0]
        if active_loans >= 2:
            return err("You already have 2 active loans on this account.")
        emi, total = calc_emi(principal, rate, years)
        conn.execute("INSERT INTO Loans (user_id,account_id,principal,annual_rate,years,emi,total_payable) VALUES (?,?,?,?,?,?,?)",
                     (session["user_id"], acc_id, principal, rate, years, emi, total))
        conn.execute("UPDATE Accounts SET balance=balance+? WHERE account_id=?", (principal, acc_id))
        conn.execute("INSERT INTO Transactions (from_account,to_account,type,amount,charges,note) VALUES (0,?,'LOAN_CREDIT',?,0.0,'Loan sanctioned and credited')",
                     (acc_id, principal))
        add_notification(conn, session["user_id"], f"Loan of ₹{principal:,.2f} sanctioned. EMI: ₹{emi:,.2f}/month.")
        conn.commit()
    return ok({"emi": emi, "total_payable": total, "months": years * 12},
              f"Loan approved! ₹{principal:,.2f} credited. Monthly EMI: ₹{emi:,.2f}")

def handle_view_loans(session, body):
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM Loans WHERE user_id=? ORDER BY loan_id DESC", (session["user_id"],)).fetchall()
    return ok([dict(r) for r in rows])

def handle_pay_emi(session, body):
    loan_id = int(body.get("loan_id", 0))
    from_acc = int(body.get("from_account_id", 0))
    with get_conn() as conn:
        loan = conn.execute("SELECT * FROM Loans WHERE loan_id=? AND user_id=? AND status='ACTIVE'",
                            (loan_id, session["user_id"])).fetchone()
        if not loan:
            return err("Active loan not found.")
        emi = loan["emi"]
        total_payable = loan["total_payable"]
        amount_paid = loan["amount_paid"]
        remaining = total_payable - amount_paid
        to_pay = min(emi, remaining)
        if not user_owns_account(conn, session["user_id"], from_acc):
            return err("Account not found or does not belong to you.")
        bal = conn.execute("SELECT balance FROM Accounts WHERE account_id=?", (from_acc,)).fetchone()["balance"]
        if bal < to_pay:
            return err(f"Insufficient balance. EMI: ₹{to_pay:,.2f}")
        new_paid = amount_paid + to_pay
        new_status = "CLOSED" if new_paid >= total_payable else "ACTIVE"
        conn.execute("UPDATE Accounts SET balance=balance-? WHERE account_id=?", (to_pay, from_acc))
        conn.execute("UPDATE Loans SET amount_paid=?, status=? WHERE loan_id=?", (new_paid, new_status, loan_id))
        conn.execute("INSERT INTO Transactions (from_account,to_account,type,amount,charges,note) VALUES (?,0,'LOAN_EMI',?,0.0,?)",
                     (from_acc, to_pay, f"EMI payment for loan #{loan_id}"))
        if new_status == "CLOSED":
            add_notification(conn, session["user_id"], f"Loan #{loan_id} fully repaid! Congratulations!")
        conn.commit()
    msg = f"EMI paid: ₹{to_pay:,.2f}. Remaining: ₹{max(0, total_payable - new_paid):,.2f}"
    if new_status == "CLOSED":
        msg = "🎉 Loan fully repaid!"
    return ok({"to_pay": to_pay, "remaining": max(0, total_payable - new_paid), "loan_closed": new_status == "CLOSED"}, msg)

# ---- BENEFICIARIES ----

def handle_add_beneficiary(session, body):
    ben_acc = int(body.get("beneficiary_account_id", 0))
    nickname = body.get("nickname", "").strip()
    uid = session["user_id"]
    with get_conn() as conn:
        owner = conn.execute("SELECT user_id FROM Accounts WHERE account_id=?", (ben_acc,)).fetchone()
        if not owner:
            return err("Beneficiary account does not exist.")
        if owner["user_id"] == uid:
            return err("You cannot add your own account as a beneficiary.")
        if not nickname:
            nickname = f"Account #{ben_acc}"
        try:
            conn.execute("INSERT OR IGNORE INTO Beneficiaries (user_id, beneficiary_account_id, nickname) VALUES (?,?,?)",
                         (uid, ben_acc, nickname))
            conn.commit()
        except sqlite3.IntegrityError:
            return err("Beneficiary already added.")
    return ok(message="Beneficiary added successfully.")

def handle_view_beneficiaries(session, body):
    with get_conn() as conn:
        rows = conn.execute("""
            SELECT b.id, b.beneficiary_account_id, b.nickname, a.type, u.name as holder_name
            FROM Beneficiaries b
            JOIN Accounts a ON b.beneficiary_account_id = a.account_id
            JOIN Users u ON a.user_id = u.id
            WHERE b.user_id=?
        """, (session["user_id"],)).fetchall()
    return ok([dict(r) for r in rows])

# ---- NOTIFICATIONS ----

def handle_notifications(session, body):
    uid = session["user_id"]
    with get_conn() as conn:
        rows = conn.execute("SELECT * FROM Notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 20", (uid,)).fetchall()
        conn.execute("UPDATE Notifications SET is_read=1 WHERE user_id=?", (uid,))
        conn.commit()
    return ok([dict(r) for r in rows])

def handle_unread_count(session, body):
    with get_conn() as conn:
        count = conn.execute("SELECT COUNT(*) FROM Notifications WHERE user_id=? AND is_read=0",
                             (session["user_id"],)).fetchone()[0]
    return ok({"count": count})

# ---- CALCULATORS ----

def handle_calc_savings(session, body):
    principal = float(body.get("principal", 0))
    rate = float(body.get("annual_rate", 0))
    years = float(body.get("years", 0))
    if principal <= 0 or rate <= 0 or years <= 0:
        return err("All values must be greater than zero.")
    si = (principal * rate * years) / 100
    ci = principal * (1 + rate / 100) ** years - principal
    return ok({
        "principal": principal, "rate": rate, "years": years,
        "simple_interest": round(si, 2), "simple_maturity": round(principal + si, 2),
        "compound_interest": round(ci, 2), "compound_maturity": round(principal + ci, 2)
    })

# ---- ADMIN ----

def admin_check(session):
    return session and session.get("role") == "Admin"

def handle_admin_users(session, body):
    if not admin_check(session): return err("Admin only.")
    with get_conn() as conn:
        rows = conn.execute("SELECT id, name, role, is_active, failed_login_attempts, created_at FROM Users ORDER BY id").fetchall()
    return ok([dict(r) for r in rows])

def handle_admin_accounts(session, body):
    if not admin_check(session): return err("Admin only.")
    with get_conn() as conn:
        rows = conn.execute("""SELECT a.account_id, u.name, a.type, a.balance, a.created_at
                               FROM Accounts a JOIN Users u ON a.user_id=u.id ORDER BY a.account_id""").fetchall()
    return ok([dict(r) for r in rows])

def handle_admin_fds(session, body):
    if not admin_check(session): return err("Admin only.")
    with get_conn() as conn:
        rows = conn.execute("SELECT f.*, u.name FROM FixedDeposits f JOIN Users u ON f.user_id=u.id ORDER BY f.fd_id DESC").fetchall()
    return ok([dict(r) for r in rows])

def handle_admin_loans(session, body):
    if not admin_check(session): return err("Admin only.")
    with get_conn() as conn:
        rows = conn.execute("SELECT l.*, u.name FROM Loans l JOIN Users u ON l.user_id=u.id ORDER BY l.loan_id DESC").fetchall()
    return ok([dict(r) for r in rows])

def handle_admin_delete_user(session, body):
    if not admin_check(session): return err("Admin only.")
    uid = int(body.get("user_id", 0))
    with get_conn() as conn:
        affected = conn.execute("DELETE FROM Users WHERE id=? AND role!='Admin'", (uid,)).rowcount
        conn.commit()
    return ok(message="User deleted." if affected > 0 else "User not found or cannot delete Admin.")

def handle_admin_unlock_user(session, body):
    if not admin_check(session): return err("Admin only.")
    uid = int(body.get("user_id", 0))
    with get_conn() as conn:
        affected = conn.execute("UPDATE Users SET failed_login_attempts=0 WHERE id=? AND role!='Admin'", (uid,)).rowcount
        conn.commit()
    return ok(message="User unlocked." if affected > 0 else "User not found.")

def handle_admin_stats(session, body):
    if not admin_check(session): return err("Admin only.")
    with get_conn() as conn:
        acc = conn.execute("SELECT COUNT(*) as cnt, COALESCE(SUM(balance),0) as total FROM Accounts").fetchone()
        loans = conn.execute("SELECT COUNT(*) as cnt, COALESCE(SUM(principal),0) as total FROM Loans WHERE status='ACTIVE'").fetchone()
        fds = conn.execute("SELECT COUNT(*) as cnt, COALESCE(SUM(principal),0) as total FROM FixedDeposits WHERE status='ACTIVE'").fetchone()
        customers = conn.execute("SELECT COUNT(*) FROM Users WHERE role!='Admin'").fetchone()[0]
        txns = conn.execute("SELECT COUNT(*) FROM Transactions").fetchone()[0]
    return ok({
        "total_accounts": acc["cnt"], "total_deposits": acc["total"],
        "active_loans": loans["cnt"], "total_loan_book": loans["total"],
        "active_fds": fds["cnt"], "total_fd_book": fds["total"],
        "total_customers": customers, "total_transactions": txns
    })

# ──────────────────────────────────────────────
# ROUTING
# ──────────────────────────────────────────────

ROUTES = {
    "/api/auth/login":           (handle_login, False),
    "/api/auth/register":        (handle_register, False),
    "/api/auth/logout":          (handle_logout, True),
    "/api/auth/change-password": (handle_change_password, True),
    "/api/accounts/create":      (handle_create_account, True),
    "/api/accounts/balance":     (handle_view_balance, True),
    "/api/accounts/deposit":     (handle_deposit, True),
    "/api/accounts/withdraw":    (handle_withdraw, True),
    "/api/accounts/transfer":    (handle_transfer, True),
    "/api/accounts/transactions":(handle_transactions, True),
    "/api/fd/create":            (handle_create_fd, True),
    "/api/fd/view":              (handle_view_fds, True),
    "/api/fd/close":             (handle_close_fd, True),
    "/api/loans/calc-emi":       (handle_calc_emi, True),
    "/api/loans/apply":          (handle_apply_loan, True),
    "/api/loans/view":           (handle_view_loans, True),
    "/api/loans/pay-emi":        (handle_pay_emi, True),
    "/api/beneficiaries/add":    (handle_add_beneficiary, True),
    "/api/beneficiaries/view":   (handle_view_beneficiaries, True),
    "/api/notifications/list":   (handle_notifications, True),
    "/api/notifications/unread": (handle_unread_count, True),
    "/api/calc/savings":         (handle_calc_savings, True),
    "/api/admin/users":          (handle_admin_users, True),
    "/api/admin/accounts":       (handle_admin_accounts, True),
    "/api/admin/fds":            (handle_admin_fds, True),
    "/api/admin/loans":          (handle_admin_loans, True),
    "/api/admin/delete-user":    (handle_admin_delete_user, True),
    "/api/admin/unlock-user":    (handle_admin_unlock_user, True),
    "/api/admin/stats":          (handle_admin_stats, True),
}

FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend")
MIME = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css",
    ".js": "application/javascript",
    ".json": "application/json",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
}

class BharatBankHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # Suppress default logging

    def send_json(self, data, status=200):
        body = json.dumps(data, default=str).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/":
            path = "/index.html"
        file_path = os.path.join(FRONTEND_DIR, path.lstrip("/"))
        if os.path.isfile(file_path):
            ext = os.path.splitext(file_path)[1]
            mime = MIME.get(ext, "application/octet-stream")
            with open(file_path, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif path.startswith("/api/"):
            self.send_json(err("Use POST for API calls."), 405)
        else:
            # SPA fallback
            index_path = os.path.join(FRONTEND_DIR, "index.html")
            if os.path.isfile(index_path):
                with open(index_path, "rb") as f:
                    body = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", len(body))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_json(err("Not found."), 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path not in ROUTES:
            self.send_json(err("Endpoint not found."), 404)
            return
        handler_fn, needs_auth = ROUTES[path]
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length)) if length > 0 else {}
        except Exception:
            self.send_json(err("Invalid JSON body."), 400)
            return
        session = None
        if needs_auth:
            token = body.get("token") or self.headers.get("Authorization", "").replace("Bearer ", "")
            session = get_session(token)
            if not session:
                self.send_json(err("Unauthorized. Please login."), 401)
                return
        try:
            result = handler_fn(session, body) if needs_auth else handler_fn(body)
            self.send_json(result)
        except (ValueError, TypeError) as e:
            self.send_json(err(f"Invalid input: {str(e)}"), 400)
        except Exception as e:
            self.send_json(err(f"Server error: {str(e)}"), 500)

if __name__ == "__main__":
    init_db()
    server = HTTPServer(("0.0.0.0", PORT), BharatBankHandler)
    print(f"""
╔══════════════════════════════════════════════════╗
║   🏦  BharatBank Server — Aapka Bank            ║
╠══════════════════════════════════════════════════╣
║  Server running at: http://localhost:{PORT}        ║
║  Open your browser and navigate to the URL above ║
║  Default admin: admin / admin123                 ║
║  Press Ctrl+C to stop                           ║
╚══════════════════════════════════════════════════╝
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped. Dhanyavaad!")
