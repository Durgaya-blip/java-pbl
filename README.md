# 🏛️ BharatBank — आपका विश्वसनीय बैंक

A full-stack Indian banking system with a beautiful Indian-themed frontend and Java backend.

---

## 🚀 Quick Setup (Windows + MinGW)

### Step 1 — Install Java JDK (if not already)
Download JDK 11+ from: https://adoptium.net/
Make sure `javac` is in your PATH.

### Step 2 — Download SQLite JDBC Driver
1. Go to: https://github.com/xerial/sqlite-jdbc/releases
2. Download the latest `sqlite-jdbc-x.x.x.jar` file
3. **Rename it to `sqlite-jdbc.jar`**
4. **Place it in the `lib\` folder** of this project

### Step 3 — Run BharatBank
Double-click `start.bat` — it will:
- Compile the Java server
- Start the backend on port 8080
- Open your browser to http://localhost:8080

---

## 📁 Project Structure

```
bharatbank/
├── src/
│   └── BankingSystem.java     ← Java backend (HTTP server + all logic)
├── frontend/
│   └── index.html             ← Full Indian-themed UI
├── lib/
│   └── sqlite-jdbc.jar        ← YOU MUST DOWNLOAD THIS
├── start.bat                  ← Windows launcher
└── README.md
```

---

## 🔑 Default Credentials
| Role  | Username | Password |
|-------|----------|----------|
| Admin | admin    | admin123 |

---

## ✨ Features

### Customer Features
- ✅ Secure login with SHA-256 hashed passwords + salt
- ✅ Account lockout after 5 failed attempts
- ✅ Create Savings / Current accounts
- ✅ Deposit, Withdraw (with service charges for large amounts)
- ✅ Fund Transfer to any account
- ✅ Transaction History (last 50 transactions)
- ✅ Fixed Deposits with compound interest + early closure penalty
- ✅ Loan application with EMI calculation
- ✅ EMI payment with loan tracking
- ✅ Saved Beneficiaries for quick transfers
- ✅ In-app Notifications
- ✅ Savings/EMI/FD Calculator
- ✅ Password change

### Admin Features
- ✅ Bank-wide statistics dashboard
- ✅ View all users (with lock status)
- ✅ Unlock locked user accounts
- ✅ Delete customers
- ✅ View all accounts with balances

---

## 🎨 UI Theme
- **Tricolor** (Saffron, White, Green) inspired design
- **Yatra One** Devanagari display font
- **Ashoka Chakra** gold accent motifs
- Dark navy background with gold borders
- INR (₹) currency formatting throughout
- Glassmorphism cards with Indian aesthetic

---

## 🔧 Technical Stack
- **Backend**: Java 11+ with `com.sun.net.httpserver` (built-in, no extra dependencies!)
- **Database**: SQLite via JDBC
- **Frontend**: Pure HTML5 + CSS3 + Vanilla JS
- **Auth**: Session tokens + SHA-256 password hashing with salt
- **API**: RESTful JSON API on port 8080

---

## ⚠️ Troubleshooting

**"sqlite-jdbc.jar not found"** → Download from GitHub releases and place in `lib\`

**"javac not found"** → Install JDK (not JRE). Add Java to PATH.

**Browser shows blank/connection error** → Wait for "Server Started!" in the console window.

**Port 8080 in use** → Edit `BankingSystem.java`, change `8080` to another port like `8090`, recompile.
