import com.sun.net.httpserver.*;
import java.io.*;
import java.net.*;
import java.sql.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

// ==========================================
// MODELS
// ==========================================
class User {
    int id; String name; String role;
    public User(int id, String name, String role) { this.id = id; this.name = name; this.role = role; }
}

// ==========================================
// SECURITY UTILITY
// ==========================================
class SecurityUtil {
    private static final SecureRandom random = new SecureRandom();
    public static String generateSalt() {
        byte[] salt = new byte[16]; random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }
    public static String hashPassword(String password, String salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(Base64.getDecoder().decode(salt));
            byte[] hash = md.digest(password.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) { throw new RuntimeException("SHA-256 not available", e); }
    }
    public static boolean verifyPassword(String raw, String stored, String salt) {
        return hashPassword(raw, salt).equals(stored);
    }
}

// ==========================================
// DATABASE MANAGER
// ==========================================
class DatabaseManager {
    private static final String URL = "jdbc:sqlite:bharatbank.db";
    public static Connection getConnection() throws SQLException { return DriverManager.getConnection(URL); }
    public static void initializeDatabase() {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA foreign_keys = ON");
            stmt.execute("PRAGMA journal_mode = WAL");
            stmt.execute("CREATE TABLE IF NOT EXISTS Users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt TEXT NOT NULL, role TEXT NOT NULL, is_active INTEGER DEFAULT 1, failed_login_attempts INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
            stmt.execute("CREATE TABLE IF NOT EXISTS Accounts (account_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL, balance REAL DEFAULT 0.0, is_active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE, UNIQUE(user_id, type))");
            stmt.execute("CREATE TABLE IF NOT EXISTS Transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, from_account INTEGER, to_account INTEGER, type TEXT NOT NULL, amount REAL NOT NULL, charges REAL DEFAULT 0.0, note TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");
            stmt.execute("CREATE TABLE IF NOT EXISTS FixedDeposits (fd_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, source_account_id INTEGER NOT NULL, principal REAL NOT NULL, annual_rate REAL NOT NULL, years INTEGER NOT NULL, maturity_amount REAL NOT NULL, status TEXT DEFAULT 'ACTIVE', penalty_applied INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE)");
            stmt.execute("CREATE TABLE IF NOT EXISTS Loans (loan_id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, account_id INTEGER NOT NULL, principal REAL NOT NULL, annual_rate REAL NOT NULL, years INTEGER NOT NULL, emi REAL NOT NULL, total_payable REAL NOT NULL, amount_paid REAL DEFAULT 0.0, status TEXT DEFAULT 'ACTIVE', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE)");
            stmt.execute("CREATE TABLE IF NOT EXISTS Beneficiaries (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, beneficiary_account_id INTEGER NOT NULL, nickname TEXT, added_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE, UNIQUE(user_id, beneficiary_account_id))");
            stmt.execute("CREATE TABLE IF NOT EXISTS Notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, message TEXT NOT NULL, is_read INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE)");
            String adminSalt = SecurityUtil.generateSalt();
            String adminHash = SecurityUtil.hashPassword("admin123", adminSalt);
            try (PreparedStatement pstmt = conn.prepareStatement("INSERT OR IGNORE INTO Users (id, name, password_hash, salt, role) VALUES (?, ?, ?, ?, ?)")) {
                pstmt.setInt(1, 1); pstmt.setString(2, "admin"); pstmt.setString(3, adminHash); pstmt.setString(4, adminSalt); pstmt.setString(5, "Admin");
                pstmt.executeUpdate();
            }
            System.out.println("[DB] Database initialized.");
        } catch (SQLException e) { System.err.println("[DB ERROR] " + e.getMessage()); }
    }
}

// ==========================================
// AUTH SERVICE
// ==========================================
class AuthService {
    private static final int MAX_ATTEMPTS = 5;
    public User login(String name, String password) {
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("SELECT * FROM Users WHERE name = ? AND is_active = 1")) {
            ps.setString(1, name);
            ResultSet rs = ps.executeQuery();
            if (rs.next()) {
                if (rs.getInt("failed_login_attempts") >= MAX_ATTEMPTS) return null;
                if (SecurityUtil.verifyPassword(password, rs.getString("password_hash"), rs.getString("salt"))) {
                    try (PreparedStatement up = conn.prepareStatement("UPDATE Users SET failed_login_attempts = 0 WHERE id = ?")) { up.setInt(1, rs.getInt("id")); up.executeUpdate(); }
                    return new User(rs.getInt("id"), rs.getString("name"), rs.getString("role"));
                } else {
                    try (PreparedStatement up = conn.prepareStatement("UPDATE Users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?")) { up.setInt(1, rs.getInt("id")); up.executeUpdate(); }
                }
            }
        } catch (SQLException e) { System.err.println("[AUTH] " + e.getMessage()); }
        return null;
    }
    public boolean register(String name, String password) {
        if (name.trim().isEmpty() || password.length() < 6) return false;
        String salt = SecurityUtil.generateSalt(); String hash = SecurityUtil.hashPassword(password, salt);
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("INSERT INTO Users (name, password_hash, salt, role) VALUES (?, ?, ?, ?)")) {
            ps.setString(1, name.trim()); ps.setString(2, hash); ps.setString(3, salt); ps.setString(4, "Customer");
            ps.executeUpdate(); return true;
        } catch (SQLException e) { return false; }
    }
    public boolean changePassword(int userId, String oldPwd, String newPwd) {
        if (newPwd.length() < 6) return false;
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("SELECT password_hash, salt FROM Users WHERE id = ?")) {
            ps.setInt(1, userId); ResultSet rs = ps.executeQuery();
            if (rs.next() && SecurityUtil.verifyPassword(oldPwd, rs.getString("password_hash"), rs.getString("salt"))) {
                String ns = SecurityUtil.generateSalt(); String nh = SecurityUtil.hashPassword(newPwd, ns);
                try (PreparedStatement up = conn.prepareStatement("UPDATE Users SET password_hash = ?, salt = ? WHERE id = ?")) { up.setString(1, nh); up.setString(2, ns); up.setInt(3, userId); up.executeUpdate(); return true; }
            }
        } catch (SQLException e) { System.err.println("[AUTH] " + e.getMessage()); }
        return false;
    }
}

// ==========================================
// BANK SERVICE
// ==========================================
class BankService {
    private static final double LARGE_WITHDRAWAL_CHARGE_RATE = 0.01;
    private static final double LARGE_WITHDRAWAL_THRESHOLD = 10000.0;
    private static final double EARLY_FD_PENALTY_RATE = 0.01;
    private static final double MIN_BALANCE_SAVINGS = 500.0;

    private boolean userOwnsAccount(Connection conn, int userId, int accId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM Accounts WHERE account_id = ? AND user_id = ? AND is_active = 1")) {
            ps.setInt(1, accId); ps.setInt(2, userId); return ps.executeQuery().next();
        }
    }
    private double getBalance(Connection conn, int accId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT balance FROM Accounts WHERE account_id = ?")) {
            ps.setInt(1, accId); ResultSet rs = ps.executeQuery(); if (rs.next()) return rs.getDouble("balance");
            throw new SQLException("Account not found");
        }
    }
    private String getAccountType(Connection conn, int accId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT type FROM Accounts WHERE account_id = ?")) {
            ps.setInt(1, accId); ResultSet rs = ps.executeQuery(); return rs.next() ? rs.getString("type") : "Unknown";
        }
    }
    private void updateBalance(Connection conn, int accId, double amount) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("UPDATE Accounts SET balance = balance + ? WHERE account_id = ?")) {
            ps.setDouble(1, amount); ps.setInt(2, accId); if (ps.executeUpdate() == 0) throw new SQLException("Account not found");
        }
    }
    private boolean accountExists(Connection conn, int accId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM Accounts WHERE account_id = ? AND is_active = 1")) {
            ps.setInt(1, accId); return ps.executeQuery().next();
        }
    }
    private int getAccountOwner(Connection conn, int accId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT user_id FROM Accounts WHERE account_id = ?")) {
            ps.setInt(1, accId); ResultSet rs = ps.executeQuery(); return rs.next() ? rs.getInt("user_id") : -1;
        }
    }
    private void logTransaction(Connection conn, int from, int to, String type, double amount, double charges, String note) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("INSERT INTO Transactions (from_account, to_account, type, amount, charges, note) VALUES (?, ?, ?, ?, ?, ?)")) {
            ps.setInt(1, from); ps.setInt(2, to); ps.setString(3, type); ps.setDouble(4, amount); ps.setDouble(5, charges); ps.setString(6, note); ps.executeUpdate();
        }
    }
    public void addNotification(int userId, String message) {
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("INSERT INTO Notifications (user_id, message) VALUES (?, ?)")) {
            ps.setInt(1, userId); ps.setString(2, message); ps.executeUpdate();
        } catch (SQLException e) {}
    }

    // Returns JSON string of accounts
    public String getAccountsJson(int userId) {
        StringBuilder sb = new StringBuilder("[");
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("SELECT account_id, type, balance, created_at FROM Accounts WHERE user_id = ? AND is_active = 1")) {
            ps.setInt(1, userId); ResultSet rs = ps.executeQuery(); boolean first = true;
            while (rs.next()) {
                if (!first) sb.append(","); first = false;
                sb.append(String.format("{\"account_id\":%d,\"type\":\"%s\",\"balance\":%.2f,\"created_at\":\"%s\"}",
                    rs.getInt("account_id"), rs.getString("type"), rs.getDouble("balance"), rs.getString("created_at")));
            }
        } catch (SQLException e) {}
        return sb.append("]").toString();
    }

    public String createAccount(int userId, String type) {
        if (!type.equals("Savings") && !type.equals("Current")) return "{\"success\":false,\"message\":\"Invalid account type\"}";
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("INSERT INTO Accounts (user_id, type, balance) VALUES (?, ?, 0.0)")) {
            ps.setInt(1, userId); ps.setString(2, type); ps.executeUpdate();
            addNotification(userId, "New " + type + " account opened.");
            return "{\"success\":true,\"message\":\"" + type + " account created successfully!\"}";
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"You may already have a " + type + " account.\"}"; }
    }

    public String deposit(int userId, int accId, double amount) {
        if (amount <= 0) return "{\"success\":false,\"message\":\"Amount must be greater than zero.\"}";
        if (amount > 1000000) return "{\"success\":false,\"message\":\"Single deposit limit is ₹10,00,000.\"}";
        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);
            if (!userOwnsAccount(conn, userId, accId)) return "{\"success\":false,\"message\":\"Account not found or does not belong to you.\"}";
            updateBalance(conn, accId, amount);
            logTransaction(conn, 0, accId, "Deposit", amount, 0.0, "Cash deposit");
            conn.commit();
            double bal = getBalance(conn, accId);
            addNotification(userId, String.format("Deposited ₹%.2f to account #%d.", amount, accId));
            return String.format("{\"success\":true,\"message\":\"Deposit successful!\",\"new_balance\":%.2f}", bal);
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"Deposit failed.\"}"; }
    }

    public String withdraw(int userId, int accId, double amount) {
        if (amount <= 0) return "{\"success\":false,\"message\":\"Amount must be greater than zero.\"}";
        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);
            if (!userOwnsAccount(conn, userId, accId)) return "{\"success\":false,\"message\":\"Account not found or does not belong to you.\"}";
            double balance = getBalance(conn, accId);
            double charges = (amount >= LARGE_WITHDRAWAL_THRESHOLD) ? amount * LARGE_WITHDRAWAL_CHARGE_RATE : 0.0;
            double total = amount + charges;
            String type = getAccountType(conn, accId);
            if ("Savings".equalsIgnoreCase(type) && (balance - total) < MIN_BALANCE_SAVINGS)
                return String.format("{\"success\":false,\"message\":\"Savings accounts must maintain minimum balance of ₹%.0f.\"}",MIN_BALANCE_SAVINGS);
            if (balance < total)
                return String.format("{\"success\":false,\"message\":\"Insufficient balance. Required ₹%.2f, Available ₹%.2f.\"}",total,balance);
            updateBalance(conn, accId, -total);
            logTransaction(conn, accId, 0, "Withdraw", amount, charges, charges > 0 ? "Large withdrawal charge applied" : "Regular withdrawal");
            conn.commit();
            double newBal = getBalance(conn, accId);
            addNotification(userId, String.format("Withdrew ₹%.2f from account #%d.", amount, accId));
            return String.format("{\"success\":true,\"message\":\"Withdrawal successful!\",\"amount\":%.2f,\"charges\":%.2f,\"total_deducted\":%.2f,\"new_balance\":%.2f}",
                amount, charges, total, newBal);
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"Withdrawal failed.\"}"; }
    }

    public String transfer(int userId, int from, int to, double amount) {
        if (from == to) return "{\"success\":false,\"message\":\"Cannot transfer to the same account.\"}";
        if (amount <= 0) return "{\"success\":false,\"message\":\"Amount must be positive.\"}";
        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);
            if (!userOwnsAccount(conn, userId, from)) return "{\"success\":false,\"message\":\"Source account not found or does not belong to you.\"}";
            if (!accountExists(conn, to)) return "{\"success\":false,\"message\":\"Destination account does not exist.\"}";
            double balance = getBalance(conn, from);
            if (balance < amount) return String.format("{\"success\":false,\"message\":\"Insufficient balance. Available ₹%.2f.\"}", balance);
            updateBalance(conn, from, -amount);
            updateBalance(conn, to, amount);
            logTransaction(conn, from, to, "Transfer", amount, 0.0, "Fund transfer");
            conn.commit();
            int destUser = getAccountOwner(conn, to);
            if (destUser != userId) addNotification(destUser, String.format("Received ₹%.2f in account #%d.", amount, to));
            addNotification(userId, String.format("Transferred ₹%.2f to account #%d.", amount, to));
            return "{\"success\":true,\"message\":\"Transfer successful!\"}";
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"Transfer failed.\"}"; }
    }

    public String getTransactions(int userId, int accId) {
        try (Connection conn = DatabaseManager.getConnection()) {
            if (!userOwnsAccount(conn, userId, accId)) return "{\"success\":false,\"message\":\"Access denied.\"}";
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"Error.\"}"; }
        StringBuilder sb = new StringBuilder("{\"success\":true,\"transactions\":[");
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("SELECT * FROM Transactions WHERE from_account = ? OR to_account = ? ORDER BY timestamp DESC LIMIT 50")) {
            ps.setInt(1, accId); ps.setInt(2, accId); ResultSet rs = ps.executeQuery(); boolean first = true;
            while (rs.next()) {
                if (!first) sb.append(","); first = false;
                sb.append(String.format("{\"id\":%d,\"type\":\"%s\",\"amount\":%.2f,\"charges\":%.2f,\"from\":%d,\"to\":%d,\"note\":\"%s\",\"timestamp\":\"%s\"}",
                    rs.getInt("id"), rs.getString("type"), rs.getDouble("amount"), rs.getDouble("charges"),
                    rs.getInt("from_account"), rs.getInt("to_account"),
                    rs.getString("note") != null ? rs.getString("note").replace("\"","'") : "",
                    rs.getString("timestamp")));
            }
        } catch (SQLException e) {}
        return sb.append("]}").toString();
    }

    public String createFD(int userId, int accId, double principal, double rate, int years) {
        if (principal < 1000) return "{\"success\":false,\"message\":\"Minimum FD amount is ₹1,000.\"}";
        if (rate <= 0 || years <= 0) return "{\"success\":false,\"message\":\"Invalid FD values.\"}";
        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);
            if (!userOwnsAccount(conn, userId, accId)) return "{\"success\":false,\"message\":\"Account not found.\"}";
            if (getBalance(conn, accId) < principal) return "{\"success\":false,\"message\":\"Insufficient balance.\"}";
            double maturity = principal * Math.pow(1 + rate / 100.0, years);
            updateBalance(conn, accId, -principal);
            try (PreparedStatement ps = conn.prepareStatement("INSERT INTO FixedDeposits (user_id, source_account_id, principal, annual_rate, years, maturity_amount) VALUES (?, ?, ?, ?, ?, ?)")) {
                ps.setInt(1, userId); ps.setInt(2, accId); ps.setDouble(3, principal); ps.setDouble(4, rate); ps.setInt(5, years); ps.setDouble(6, maturity); ps.executeUpdate();
            }
            logTransaction(conn, accId, 0, "FD_CREATE", principal, 0.0, "Fixed Deposit opened");
            conn.commit();
            addNotification(userId, String.format("FD of ₹%.2f created. Matures at ₹%.2f.", principal, maturity));
            return String.format("{\"success\":true,\"message\":\"FD created! Maturity: ₹%.2f after %d year(s).\",\"maturity\":%.2f}", maturity, years, maturity);
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"FD creation failed.\"}"; }
    }

    public String getFDs(int userId) {
        StringBuilder sb = new StringBuilder("{\"success\":true,\"fds\":[");
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("SELECT * FROM FixedDeposits WHERE user_id = ? ORDER BY fd_id DESC")) {
            ps.setInt(1, userId); ResultSet rs = ps.executeQuery(); boolean first = true;
            while (rs.next()) {
                if (!first) sb.append(","); first = false;
                sb.append(String.format("{\"fd_id\":%d,\"source_account_id\":%d,\"principal\":%.2f,\"annual_rate\":%.2f,\"years\":%d,\"maturity_amount\":%.2f,\"status\":\"%s\",\"created_at\":\"%s\"}",
                    rs.getInt("fd_id"), rs.getInt("source_account_id"), rs.getDouble("principal"), rs.getDouble("annual_rate"),
                    rs.getInt("years"), rs.getDouble("maturity_amount"), rs.getString("status"), rs.getString("created_at")));
            }
        } catch (SQLException e) {}
        return sb.append("]}").toString();
    }

    public String closeFD(int userId, int fdId, boolean early) {
        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM FixedDeposits WHERE fd_id = ? AND user_id = ? AND status = 'ACTIVE'")) {
                ps.setInt(1, fdId); ps.setInt(2, userId); ResultSet rs = ps.executeQuery();
                if (!rs.next()) return "{\"success\":false,\"message\":\"Active FD not found.\"}";
                int srcAcc = rs.getInt("source_account_id");
                double maturity = rs.getDouble("maturity_amount"), principal = rs.getDouble("principal");
                double penalty = 0, credited = maturity;
                if (early) { penalty = principal * EARLY_FD_PENALTY_RATE; credited = principal - penalty; }
                updateBalance(conn, srcAcc, credited);
                try (PreparedStatement up = conn.prepareStatement("UPDATE FixedDeposits SET status = 'CLOSED', penalty_applied = ? WHERE fd_id = ?")) {
                    up.setInt(1, early ? 1 : 0); up.setInt(2, fdId); up.executeUpdate();
                }
                logTransaction(conn, 0, srcAcc, early ? "FD_EARLY_CLOSE" : "FD_CLOSE", credited, penalty, early ? "Early FD closure" : "FD maturity credited");
                conn.commit();
                return String.format("{\"success\":true,\"message\":\"FD closed. ₹%.2f credited.\",\"credited\":%.2f,\"penalty\":%.2f}", credited, credited, penalty);
            }
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"FD closure failed.\"}"; }
    }

    public String applyLoan(int userId, int accId, double principal, double rate, int years) {
        if (principal < 5000) return "{\"success\":false,\"message\":\"Minimum loan amount is ₹5,000.\"}";
        if (principal > 5000000) return "{\"success\":false,\"message\":\"Maximum loan limit is ₹50,00,000.\"}";
        if (rate <= 0 || years <= 0) return "{\"success\":false,\"message\":\"Invalid loan values.\"}";
        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);
            if (!userOwnsAccount(conn, userId, accId)) return "{\"success\":false,\"message\":\"Account not found.\"}";
            try (PreparedStatement chk = conn.prepareStatement("SELECT COUNT(*) FROM Loans WHERE user_id = ? AND account_id = ? AND status = 'ACTIVE'")) {
                chk.setInt(1, userId); chk.setInt(2, accId); ResultSet cr = chk.executeQuery();
                if (cr.next() && cr.getInt(1) >= 2) return "{\"success\":false,\"message\":\"You already have 2 active loans on this account.\"}";
            }
            int months = years * 12; double mr = rate / (12 * 100.0);
            double emi = (principal * mr * Math.pow(1 + mr, months)) / (Math.pow(1 + mr, months) - 1);
            double total = emi * months;
            try (PreparedStatement ps = conn.prepareStatement("INSERT INTO Loans (user_id, account_id, principal, annual_rate, years, emi, total_payable) VALUES (?, ?, ?, ?, ?, ?, ?)")) {
                ps.setInt(1, userId); ps.setInt(2, accId); ps.setDouble(3, principal); ps.setDouble(4, rate); ps.setInt(5, years); ps.setDouble(6, emi); ps.setDouble(7, total); ps.executeUpdate();
            }
            updateBalance(conn, accId, principal);
            logTransaction(conn, 0, accId, "LOAN_CREDIT", principal, 0.0, "Loan sanctioned");
            conn.commit();
            addNotification(userId, String.format("Loan of ₹%.2f sanctioned. EMI: ₹%.2f/month.", principal, emi));
            return String.format("{\"success\":true,\"message\":\"Loan approved! EMI: ₹%.2f/month for %d months.\",\"emi\":%.2f,\"total\":%.2f}", emi, months, emi, total);
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"Loan processing failed.\"}"; }
    }

    public String getLoans(int userId) {
        StringBuilder sb = new StringBuilder("{\"success\":true,\"loans\":[");
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("SELECT * FROM Loans WHERE user_id = ? ORDER BY loan_id DESC")) {
            ps.setInt(1, userId); ResultSet rs = ps.executeQuery(); boolean first = true;
            while (rs.next()) {
                if (!first) sb.append(","); first = false;
                double rem = rs.getDouble("total_payable") - rs.getDouble("amount_paid");
                sb.append(String.format("{\"loan_id\":%d,\"account_id\":%d,\"principal\":%.2f,\"annual_rate\":%.2f,\"emi\":%.2f,\"amount_paid\":%.2f,\"remaining\":%.2f,\"status\":\"%s\"}",
                    rs.getInt("loan_id"), rs.getInt("account_id"), rs.getDouble("principal"), rs.getDouble("annual_rate"),
                    rs.getDouble("emi"), rs.getDouble("amount_paid"), rem, rs.getString("status")));
            }
        } catch (SQLException e) {}
        return sb.append("]}").toString();
    }

    public String payEMI(int userId, int loanId, int fromAcc) {
        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);
            try (PreparedStatement ps = conn.prepareStatement("SELECT * FROM Loans WHERE loan_id = ? AND user_id = ? AND status = 'ACTIVE'")) {
                ps.setInt(1, loanId); ps.setInt(2, userId); ResultSet rs = ps.executeQuery();
                if (!rs.next()) return "{\"success\":false,\"message\":\"Active loan not found.\"}";
                double emi = rs.getDouble("emi"), total = rs.getDouble("total_payable"), paid = rs.getDouble("amount_paid");
                double toPay = Math.min(emi, total - paid);
                if (!userOwnsAccount(conn, userId, fromAcc)) return "{\"success\":false,\"message\":\"Account not found.\"}";
                if (getBalance(conn, fromAcc) < toPay) return String.format("{\"success\":false,\"message\":\"Insufficient balance. EMI: ₹%.2f.\"}", toPay);
                updateBalance(conn, fromAcc, -toPay);
                double newPaid = paid + toPay;
                String status = (newPaid >= total) ? "CLOSED" : "ACTIVE";
                try (PreparedStatement up = conn.prepareStatement("UPDATE Loans SET amount_paid = ?, status = ? WHERE loan_id = ?")) {
                    up.setDouble(1, newPaid); up.setString(2, status); up.setInt(3, loanId); up.executeUpdate();
                }
                logTransaction(conn, fromAcc, 0, "LOAN_EMI", toPay, 0.0, "EMI for loan #" + loanId);
                conn.commit();
                if ("CLOSED".equals(status)) addNotification(userId, "Loan #" + loanId + " fully repaid!");
                return String.format("{\"success\":true,\"message\":\"%s\",\"paid\":%.2f,\"remaining\":%.2f}",
                    "CLOSED".equals(status) ? "Loan fully repaid! Congratulations!" : "EMI paid successfully!",
                    toPay, total - newPaid);
            }
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"EMI payment failed.\"}"; }
    }

    public String getNotifications(int userId) {
        StringBuilder sb = new StringBuilder("{\"success\":true,\"notifications\":[");
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("SELECT * FROM Notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 20")) {
            ps.setInt(1, userId); ResultSet rs = ps.executeQuery(); boolean first = true;
            while (rs.next()) {
                if (!first) sb.append(","); first = false;
                sb.append(String.format("{\"id\":%d,\"message\":\"%s\",\"is_read\":%d,\"created_at\":\"%s\"}",
                    rs.getInt("id"), rs.getString("message").replace("\"","'"), rs.getInt("is_read"), rs.getString("created_at")));
            }
            try (PreparedStatement up = conn.prepareStatement("UPDATE Notifications SET is_read = 1 WHERE user_id = ?")) { up.setInt(1, userId); up.executeUpdate(); }
        } catch (SQLException e) {}
        return sb.append("]}").toString();
    }

    public String getUnreadCount(int userId) {
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("SELECT COUNT(*) FROM Notifications WHERE user_id = ? AND is_read = 0")) {
            ps.setInt(1, userId); ResultSet rs = ps.executeQuery();
            if (rs.next()) return "{\"count\":" + rs.getInt(1) + "}";
        } catch (SQLException e) {}
        return "{\"count\":0}";
    }

    public String addBeneficiary(int userId, int benAccId, String nickname) {
        try (Connection conn = DatabaseManager.getConnection()) {
            if (!accountExists(conn, benAccId)) return "{\"success\":false,\"message\":\"Beneficiary account does not exist.\"}";
            if (getAccountOwner(conn, benAccId) == userId) return "{\"success\":false,\"message\":\"Cannot add your own account.\"}";
            try (PreparedStatement ps = conn.prepareStatement("INSERT OR IGNORE INTO Beneficiaries (user_id, beneficiary_account_id, nickname) VALUES (?, ?, ?)")) {
                ps.setInt(1, userId); ps.setInt(2, benAccId); ps.setString(3, nickname.isEmpty() ? "Account #" + benAccId : nickname);
                ps.executeUpdate(); return "{\"success\":true,\"message\":\"Beneficiary added!\"}";
            }
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"Error adding beneficiary.\"}"; }
    }

    public String getBeneficiaries(int userId) {
        StringBuilder sb = new StringBuilder("{\"success\":true,\"beneficiaries\":[");
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement(
                "SELECT b.id, b.beneficiary_account_id, b.nickname, a.type, u.name FROM Beneficiaries b JOIN Accounts a ON b.beneficiary_account_id = a.account_id JOIN Users u ON a.user_id = u.id WHERE b.user_id = ?")) {
            ps.setInt(1, userId); ResultSet rs = ps.executeQuery(); boolean first = true;
            while (rs.next()) {
                if (!first) sb.append(","); first = false;
                sb.append(String.format("{\"id\":%d,\"account_id\":%d,\"nickname\":\"%s\",\"type\":\"%s\",\"holder\":\"%s\"}",
                    rs.getInt("id"), rs.getInt("beneficiary_account_id"), rs.getString("nickname"), rs.getString("type"), rs.getString("name")));
            }
        } catch (SQLException e) {}
        return sb.append("]}").toString();
    }

    // Admin methods
    public String getAllUsers() {
        StringBuilder sb = new StringBuilder("{\"success\":true,\"users\":[");
        try (Connection conn = DatabaseManager.getConnection(); Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery("SELECT id, name, role, is_active, failed_login_attempts, created_at FROM Users ORDER BY id")) {
            boolean first = true;
            while (rs.next()) {
                if (!first) sb.append(","); first = false;
                sb.append(String.format("{\"id\":%d,\"name\":\"%s\",\"role\":\"%s\",\"is_active\":%d,\"failed_attempts\":%d,\"created_at\":\"%s\"}",
                    rs.getInt("id"), rs.getString("name"), rs.getString("role"), rs.getInt("is_active"), rs.getInt("failed_login_attempts"), rs.getString("created_at")));
            }
        } catch (SQLException e) {}
        return sb.append("]}").toString();
    }

    public String getAllAccounts() {
        StringBuilder sb = new StringBuilder("{\"success\":true,\"accounts\":[");
        try (Connection conn = DatabaseManager.getConnection(); Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery("SELECT a.account_id, u.name, a.type, a.balance, a.created_at FROM Accounts a JOIN Users u ON a.user_id = u.id ORDER BY a.account_id")) {
            boolean first = true;
            while (rs.next()) {
                if (!first) sb.append(","); first = false;
                sb.append(String.format("{\"account_id\":%d,\"user\":\"%s\",\"type\":\"%s\",\"balance\":%.2f,\"created_at\":\"%s\"}",
                    rs.getInt("account_id"), rs.getString("name"), rs.getString("type"), rs.getDouble("balance"), rs.getString("created_at")));
            }
        } catch (SQLException e) {}
        return sb.append("]}").toString();
    }

    public String getBankStats() {
        try (Connection conn = DatabaseManager.getConnection(); Statement stmt = conn.createStatement()) {
            ResultSet r1 = stmt.executeQuery("SELECT COUNT(*) as cnt, COALESCE(SUM(balance),0) as total FROM Accounts");
            int accCount = 0; double totalDep = 0;
            if (r1.next()) { accCount = r1.getInt("cnt"); totalDep = r1.getDouble("total"); }
            ResultSet r2 = stmt.executeQuery("SELECT COUNT(*) as cnt, COALESCE(SUM(principal),0) as total FROM Loans WHERE status='ACTIVE'");
            int loanCount = 0; double totalLoans = 0;
            if (r2.next()) { loanCount = r2.getInt("cnt"); totalLoans = r2.getDouble("total"); }
            ResultSet r3 = stmt.executeQuery("SELECT COUNT(*) as cnt, COALESCE(SUM(principal),0) as total FROM FixedDeposits WHERE status='ACTIVE'");
            int fdCount = 0; double totalFDs = 0;
            if (r3.next()) { fdCount = r3.getInt("cnt"); totalFDs = r3.getDouble("total"); }
            ResultSet r4 = stmt.executeQuery("SELECT COUNT(*) as cnt FROM Users WHERE role != 'Admin'");
            int customers = 0; if (r4.next()) customers = r4.getInt("cnt");
            return String.format("{\"success\":true,\"accounts\":%d,\"total_deposits\":%.2f,\"active_loans\":%d,\"total_loan_book\":%.2f,\"active_fds\":%d,\"total_fd_book\":%.2f,\"customers\":%d}",
                accCount, totalDep, loanCount, totalLoans, fdCount, totalFDs, customers);
        } catch (SQLException e) { return "{\"success\":false}"; }
    }

    public String deleteUser(int userId) {
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("DELETE FROM Users WHERE id = ? AND role != 'Admin'")) {
            ps.setInt(1, userId); int n = ps.executeUpdate();
            return n > 0 ? "{\"success\":true,\"message\":\"User deleted.\"}" : "{\"success\":false,\"message\":\"User not found or cannot delete admin.\"}";
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"Delete failed.\"}"; }
    }

    public String unlockUser(int userId) {
        try (Connection conn = DatabaseManager.getConnection(); PreparedStatement ps = conn.prepareStatement("UPDATE Users SET failed_login_attempts = 0 WHERE id = ? AND role != 'Admin'")) {
            ps.setInt(1, userId); int n = ps.executeUpdate();
            return n > 0 ? "{\"success\":true,\"message\":\"User unlocked.\"}" : "{\"success\":false,\"message\":\"User not found.\"}";
        } catch (SQLException e) { return "{\"success\":false,\"message\":\"Unlock failed.\"}"; }
    }
}

// ==========================================
// SESSION MANAGER
// ==========================================
class SessionManager {
    private static final Map<String, User> sessions = new ConcurrentHashMap<>();
    public static String createSession(User user) {
        String token = UUID.randomUUID().toString();
        sessions.put(token, user);
        return token;
    }
    public static User getUser(String token) { return token != null ? sessions.get(token) : null; }
    public static void removeSession(String token) { if (token != null) sessions.remove(token); }
}

// ==========================================
// HTTP SERVER
// ==========================================
public class BankingSystem {
    private static final AuthService authService = new AuthService();
    private static final BankService bankService = new BankService();

    public static void main(String[] args) throws Exception {
        // Load SQLite driver
        try { Class.forName("org.sqlite.JDBC"); } catch (ClassNotFoundException e) {
            System.err.println("SQLite JDBC driver not found! Make sure sqlite-jdbc.jar is in the same folder.");
            System.exit(1);
        }
        DatabaseManager.initializeDatabase();

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);
        server.createContext("/api/login", BankingSystem::handleLogin);
        server.createContext("/api/register", BankingSystem::handleRegister);
        server.createContext("/api/logout", BankingSystem::handleLogout);
        server.createContext("/api/accounts", BankingSystem::handleAccounts);
        server.createContext("/api/deposit", BankingSystem::handleDeposit);
        server.createContext("/api/withdraw", BankingSystem::handleWithdraw);
        server.createContext("/api/transfer", BankingSystem::handleTransfer);
        server.createContext("/api/transactions", BankingSystem::handleTransactions);
        server.createContext("/api/fd/create", BankingSystem::handleFDCreate);
        server.createContext("/api/fd/list", BankingSystem::handleFDList);
        server.createContext("/api/fd/close", BankingSystem::handleFDClose);
        server.createContext("/api/loan/apply", BankingSystem::handleLoanApply);
        server.createContext("/api/loan/list", BankingSystem::handleLoanList);
        server.createContext("/api/loan/pay", BankingSystem::handleLoanPay);
        server.createContext("/api/notifications", BankingSystem::handleNotifications);
        server.createContext("/api/notifications/count", BankingSystem::handleNotificationCount);
        server.createContext("/api/beneficiary/add", BankingSystem::handleBeneficiaryAdd);
        server.createContext("/api/beneficiary/list", BankingSystem::handleBeneficiaryList);
        server.createContext("/api/password/change", BankingSystem::handlePasswordChange);
        server.createContext("/api/admin/users", BankingSystem::handleAdminUsers);
        server.createContext("/api/admin/accounts", BankingSystem::handleAdminAccounts);
        server.createContext("/api/admin/stats", BankingSystem::handleAdminStats);
        server.createContext("/api/admin/delete", BankingSystem::handleAdminDelete);
        server.createContext("/api/admin/unlock", BankingSystem::handleAdminUnlock);
        server.createContext("/", BankingSystem::handleStatic);
        server.setExecutor(Executors.newFixedThreadPool(10));
        server.start();

        System.out.println("╔══════════════════════════════════════════╗");
        System.out.println("║   BharatBank Server Started!             ║");
        System.out.println("║   Open: http://localhost:8080            ║");
        System.out.println("║   Admin: admin / admin123                ║");
        System.out.println("╚══════════════════════════════════════════╝");
    }

    // --- Static file server ---
    static void handleStatic(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        if (path.equals("/")) path = "/index.html";
        File f = new File("frontend" + path);
        if (!f.exists() || !f.isFile()) { send(ex, 404, "text/plain", "Not Found"); return; }
        String ct = path.endsWith(".html") ? "text/html" : path.endsWith(".css") ? "text/css" : path.endsWith(".js") ? "application/javascript" : "application/octet-stream";
        byte[] data = java.nio.file.Files.readAllBytes(f.toPath());
        ex.getResponseHeaders().set("Content-Type", ct);
        ex.sendResponseHeaders(200, data.length);
        ex.getResponseBody().write(data);
        ex.getResponseBody().close();
    }

    // --- Auth ---
    static void handleLogin(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("POST")) { send(ex, 405, "application/json", "{\"error\":\"Method not allowed\"}"); return; }
        Map<String,String> body = parseBody(ex);
        User user = authService.login(body.get("username"), body.get("password"));
        if (user != null) {
            String token = SessionManager.createSession(user);
            send(ex, 200, "application/json", String.format("{\"success\":true,\"token\":\"%s\",\"name\":\"%s\",\"role\":\"%s\"}", token, user.name, user.role));
        } else {
            send(ex, 401, "application/json", "{\"success\":false,\"message\":\"Invalid credentials or account locked.\"}");
        }
    }

    static void handleRegister(HttpExchange ex) throws IOException {
        if (!ex.getRequestMethod().equals("POST")) { send(ex, 405, "application/json", "{\"error\":\"Method not allowed\"}"); return; }
        Map<String,String> body = parseBody(ex);
        boolean ok = authService.register(body.get("username"), body.get("password"));
        send(ex, ok ? 200 : 400, "application/json", ok ? "{\"success\":true,\"message\":\"Registered successfully!\"}" : "{\"success\":false,\"message\":\"Username taken or password too short (min 6 chars).\"}");
    }

    static void handleLogout(HttpExchange ex) throws IOException {
        String token = ex.getRequestHeaders().getFirst("Authorization");
        SessionManager.removeSession(token);
        send(ex, 200, "application/json", "{\"success\":true}");
    }

    // --- Accounts ---
    static void handleAccounts(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        if (ex.getRequestMethod().equals("GET")) {
            send(ex, 200, "application/json", bankService.getAccountsJson(user.id));
        } else if (ex.getRequestMethod().equals("POST")) {
            Map<String,String> body = parseBody(ex);
            send(ex, 200, "application/json", bankService.createAccount(user.id, body.getOrDefault("type","")));
        }
    }

    static void handleDeposit(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        Map<String,String> body = parseBody(ex);
        send(ex, 200, "application/json", bankService.deposit(user.id, parseInt(body,"account_id"), parseDouble(body,"amount")));
    }

    static void handleWithdraw(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        Map<String,String> body = parseBody(ex);
        send(ex, 200, "application/json", bankService.withdraw(user.id, parseInt(body,"account_id"), parseDouble(body,"amount")));
    }

    static void handleTransfer(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        Map<String,String> body = parseBody(ex);
        send(ex, 200, "application/json", bankService.transfer(user.id, parseInt(body,"from_account"), parseInt(body,"to_account"), parseDouble(body,"amount")));
    }

    static void handleTransactions(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        String q = ex.getRequestURI().getQuery();
        int accId = q != null && q.startsWith("account_id=") ? Integer.parseInt(q.split("=")[1]) : -1;
        send(ex, 200, "application/json", bankService.getTransactions(user.id, accId));
    }

    static void handleFDCreate(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        Map<String,String> body = parseBody(ex);
        send(ex, 200, "application/json", bankService.createFD(user.id, parseInt(body,"account_id"), parseDouble(body,"principal"), parseDouble(body,"rate"), parseInt(body,"years")));
    }

    static void handleFDList(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        send(ex, 200, "application/json", bankService.getFDs(user.id));
    }

    static void handleFDClose(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        Map<String,String> body = parseBody(ex);
        send(ex, 200, "application/json", bankService.closeFD(user.id, parseInt(body,"fd_id"), "true".equals(body.get("early"))));
    }

    static void handleLoanApply(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        Map<String,String> body = parseBody(ex);
        send(ex, 200, "application/json", bankService.applyLoan(user.id, parseInt(body,"account_id"), parseDouble(body,"principal"), parseDouble(body,"rate"), parseInt(body,"years")));
    }

    static void handleLoanList(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        send(ex, 200, "application/json", bankService.getLoans(user.id));
    }

    static void handleLoanPay(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        Map<String,String> body = parseBody(ex);
        send(ex, 200, "application/json", bankService.payEMI(user.id, parseInt(body,"loan_id"), parseInt(body,"account_id")));
    }

    static void handleNotifications(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        send(ex, 200, "application/json", bankService.getNotifications(user.id));
    }

    static void handleNotificationCount(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        send(ex, 200, "application/json", bankService.getUnreadCount(user.id));
    }

    static void handleBeneficiaryAdd(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        Map<String,String> body = parseBody(ex);
        send(ex, 200, "application/json", bankService.addBeneficiary(user.id, parseInt(body,"account_id"), body.getOrDefault("nickname","")));
    }

    static void handleBeneficiaryList(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        send(ex, 200, "application/json", bankService.getBeneficiaries(user.id));
    }

    static void handlePasswordChange(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        Map<String,String> body = parseBody(ex);
        boolean ok = authService.changePassword(user.id, body.get("old_password"), body.get("new_password"));
        send(ex, 200, "application/json", ok ? "{\"success\":true,\"message\":\"Password changed!\"}" : "{\"success\":false,\"message\":\"Old password incorrect or new password too short.\"}");
    }

    static void handleAdminUsers(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        if (!"Admin".equals(user.role)) { send(ex, 403, "application/json", "{\"error\":\"Forbidden\"}"); return; }
        send(ex, 200, "application/json", bankService.getAllUsers());
    }

    static void handleAdminAccounts(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        if (!"Admin".equals(user.role)) { send(ex, 403, "application/json", "{\"error\":\"Forbidden\"}"); return; }
        send(ex, 200, "application/json", bankService.getAllAccounts());
    }

    static void handleAdminStats(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        if (!"Admin".equals(user.role)) { send(ex, 403, "application/json", "{\"error\":\"Forbidden\"}"); return; }
        send(ex, 200, "application/json", bankService.getBankStats());
    }

    static void handleAdminDelete(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        if (!"Admin".equals(user.role)) { send(ex, 403, "application/json", "{\"error\":\"Forbidden\"}"); return; }
        Map<String,String> body = parseBody(ex);
        send(ex, 200, "application/json", bankService.deleteUser(parseInt(body,"user_id")));
    }

    static void handleAdminUnlock(HttpExchange ex) throws IOException {
        User user = auth(ex); if (user == null) return;
        if (!"Admin".equals(user.role)) { send(ex, 403, "application/json", "{\"error\":\"Forbidden\"}"); return; }
        Map<String,String> body = parseBody(ex);
        send(ex, 200, "application/json", bankService.unlockUser(parseInt(body,"user_id")));
    }

    // --- Utilities ---
    static User auth(HttpExchange ex) throws IOException {
        String token = ex.getRequestHeaders().getFirst("Authorization");
        User user = SessionManager.getUser(token);
        if (user == null) {
            send(ex, 401, "application/json", "{\"error\":\"Unauthorized\"}");
            return null;
        }
        return user;
    }

    static void send(HttpExchange ex, int code, String ct, String body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", ct + "; charset=utf-8");
        ex.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().set("Access-Control-Allow-Headers", "Authorization, Content-Type");
        ex.getResponseHeaders().set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        if (ex.getRequestMethod().equals("OPTIONS")) { ex.sendResponseHeaders(204, -1); return; }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) { os.write(bytes); }
    }

    static Map<String,String> parseBody(HttpExchange ex) throws IOException {
        String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        Map<String,String> map = new HashMap<>();
        if (body.startsWith("{")) {
            body = body.replaceAll("[{}\"]", "");
            for (String pair : body.split(",")) {
                String[] kv = pair.split(":", 2);
                if (kv.length == 2) map.put(kv[0].trim(), kv[1].trim());
            }
        } else {
            for (String pair : body.split("&")) {
                String[] kv = pair.split("=", 2);
                if (kv.length == 2) map.put(URLDecoder.decode(kv[0], "UTF-8"), URLDecoder.decode(kv[1], "UTF-8"));
            }
        }
        return map;
    }

    static int parseInt(Map<String,String> m, String key) {
        try { return Integer.parseInt(m.getOrDefault(key, "0")); } catch (NumberFormatException e) { return 0; }
    }
    static double parseDouble(Map<String,String> m, String key) {
        try { return Double.parseDouble(m.getOrDefault(key, "0")); } catch (NumberFormatException e) { return 0; }
    }
}
