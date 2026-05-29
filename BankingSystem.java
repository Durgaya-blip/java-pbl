import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Scanner;

// ==========================================
// MODELS
// ==========================================

class User {
    int id;
    String name;
    String password;
    String role;

    public User(int id, String name, String password, String role) {
        this.id = id;
        this.name = name;
        this.password = password;
        this.role = role;
    }
}

// ==========================================
// DATABASE MANAGER
// ==========================================

class DatabaseManager {
    private static final String URL = "jdbc:sqlite:bank_system.db";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL);
    }

    public static void initializeDatabase() {
        try (Connection conn = getConnection(); Statement stmt = conn.createStatement()) {
            stmt.execute("PRAGMA foreign_keys = ON");

            stmt.execute("CREATE TABLE IF NOT EXISTS Users (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "name TEXT NOT NULL UNIQUE, " +
                    "password TEXT NOT NULL, " +
                    "role TEXT NOT NULL)");

            stmt.execute("CREATE TABLE IF NOT EXISTS Accounts (" +
                    "account_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "user_id INTEGER NOT NULL, " +
                    "type TEXT NOT NULL, " +
                    "balance REAL DEFAULT 0.0, " +
                    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                    "FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE, " +
                    "UNIQUE(user_id, type))");

            stmt.execute("CREATE TABLE IF NOT EXISTS Transactions (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "from_account INTEGER, " +
                    "to_account INTEGER, " +
                    "type TEXT NOT NULL, " +
                    "amount REAL NOT NULL, " +
                    "charges REAL DEFAULT 0.0, " +
                    "note TEXT, " +
                    "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)");

            stmt.execute("CREATE TABLE IF NOT EXISTS FixedDeposits (" +
                    "fd_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "user_id INTEGER NOT NULL, " +
                    "source_account_id INTEGER NOT NULL, " +
                    "principal REAL NOT NULL, " +
                    "annual_rate REAL NOT NULL, " +
                    "years INTEGER NOT NULL, " +
                    "maturity_amount REAL NOT NULL, " +
                    "status TEXT DEFAULT 'ACTIVE', " +
                    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                    "FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE, " +
                    "FOREIGN KEY(source_account_id) REFERENCES Accounts(account_id))");

            stmt.execute("CREATE TABLE IF NOT EXISTS Loans (" +
                    "loan_id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "user_id INTEGER NOT NULL, " +
                    "account_id INTEGER NOT NULL, " +
                    "principal REAL NOT NULL, " +
                    "annual_rate REAL NOT NULL, " +
                    "years INTEGER NOT NULL, " +
                    "emi REAL NOT NULL, " +
                    "total_payable REAL NOT NULL, " +
                    "status TEXT DEFAULT 'ACTIVE', " +
                    "created_at DATETIME DEFAULT CURRENT_TIMESTAMP, " +
                    "FOREIGN KEY(user_id) REFERENCES Users(id) ON DELETE CASCADE, " +
                    "FOREIGN KEY(account_id) REFERENCES Accounts(account_id))");

            try (PreparedStatement pstmt = conn.prepareStatement(
                    "INSERT OR IGNORE INTO Users (id, name, password, role) VALUES (?, ?, ?, ?)")) {
                pstmt.setInt(1, 1);
                pstmt.setString(2, "admin");
                pstmt.setString(3, "admin123");
                pstmt.setString(4, "Admin");
                pstmt.executeUpdate();
            }
        } catch (SQLException e) {
            System.err.println("Database initialization failed: " + e.getMessage());
        }
    }
}

// ==========================================
// AUTH SERVICE
// ==========================================

class AuthService {
    public User login(String name, String password) {
        String query = "SELECT * FROM Users WHERE name = ? AND password = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, name);
            pstmt.setString(2, password);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return new User(
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getString("password"),
                        rs.getString("role")
                );
            }
        } catch (SQLException e) {
            System.err.println("Login error: " + e.getMessage());
        }
        return null;
    }

    public boolean register(String name, String password, String role) {
        String query = "INSERT INTO Users (name, password, role) VALUES (?, ?, ?)";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setString(1, name);
            pstmt.setString(2, password);
            pstmt.setString(3, role);
            pstmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            System.err.println("Registration failed (Username might be taken): " + e.getMessage());
            return false;
        }
    }
}

// ==========================================
// BANK SERVICE
// ==========================================

class BankService {

    private static final double LARGE_WITHDRAWAL_CHARGE_RATE = 0.01;
    private static final double LARGE_WITHDRAWAL_THRESHOLD = 10000.0;

    public void createAccount(int userId, String type) {
        String query = "INSERT INTO Accounts (user_id, type, balance) VALUES (?, ?, 0.0)";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setInt(1, userId);
            pstmt.setString(2, type);
            pstmt.executeUpdate();
            System.out.println("Account created successfully.");
        } catch (SQLException e) {
            System.err.println("Error creating account. You may already have a " + type + " account.");
        }
    }

    public void viewBalance(int userId) {
        String query = "SELECT account_id, type, balance, created_at FROM Accounts WHERE user_id = ?";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setInt(1, userId);
            ResultSet rs = pstmt.executeQuery();
            boolean hasAccounts = false;
            System.out.println("\\n--- Your Accounts ---");
            while (rs.next()) {
                hasAccounts = true;
                System.out.printf("Acc ID: %d | Type: %s | Balance: INR %.2f | Opened: %s%n",
                        rs.getInt("account_id"),
                        rs.getString("type"),
                        rs.getDouble("balance"),
                        rs.getString("created_at"));
            }
            if (!hasAccounts) {
                System.out.println("No accounts found. Please create one.");
            }
        } catch (SQLException e) {
            System.err.println("Error retrieving accounts: " + e.getMessage());
        }
    }

    public void depositMoney(int accountId, double amount) {
        if (amount <= 0) {
            System.out.println("Amount must be greater than zero.");
            return;
        }

        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);

            if (!accountExists(conn, accountId)) {
                System.out.println("Account does not exist.");
                return;
            }

            updateBalance(conn, accountId, amount);
            logTransaction(conn, 0, accountId, "Deposit", amount, 0.0, "Cash deposit");
            conn.commit();
            System.out.println("Deposit successful.");
        } catch (SQLException e) {
            System.err.println("Deposit failed: " + e.getMessage());
        }
    }

    public void withdrawMoney(int accountId, double amount) {
        if (amount <= 0) {
            System.out.println("Amount must be greater than zero.");
            return;
        }

        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);

            double currentBalance = getBalance(conn, accountId);
            double charges = 0.0;

            if (amount >= LARGE_WITHDRAWAL_THRESHOLD) {
                charges = amount * LARGE_WITHDRAWAL_CHARGE_RATE;
            }

            double totalDeduction = amount + charges;

            if (currentBalance < totalDeduction) {
                System.out.printf("Insufficient balance. Required: INR %.2f%n", totalDeduction);
                return;
            }

            updateBalance(conn, accountId, -totalDeduction);
            logTransaction(conn, accountId, 0, "Withdraw", amount, charges,
                    charges > 0 ? "Large withdrawal charge applied" : "Regular withdrawal");
            conn.commit();

            System.out.printf("Withdrawal successful. Amount: INR %.2f | Charges: INR %.2f | Total deducted: INR %.2f%n",
                    amount, charges, totalDeduction);
        } catch (SQLException e) {
            System.err.println("Withdrawal failed: " + e.getMessage());
        }
    }

    public void transferMoney(int fromAccount, int toAccount, double amount) {
        if (fromAccount == toAccount) {
            System.out.println("Cannot transfer to the same account.");
            return;
        }
        if (amount <= 0) {
            System.out.println("Amount must be positive.");
            return;
        }

        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);

            if (!accountExists(conn, toAccount)) {
                System.out.println("Destination account does not exist.");
                return;
            }

            if (getBalance(conn, fromAccount) < amount) {
                System.out.println("Insufficient balance for transfer.");
                return;
            }

            updateBalance(conn, fromAccount, -amount);
            updateBalance(conn, toAccount, amount);
            logTransaction(conn, fromAccount, toAccount, "Transfer", amount, 0.0, "Fund transfer");

            conn.commit();
            System.out.println("Transfer successful.");
        } catch (SQLException e) {
            System.err.println("Transfer failed: " + e.getMessage());
        }
    }

    public void viewTransactionHistory(int accountId) {
        String query = "SELECT * FROM Transactions WHERE from_account = ? OR to_account = ? ORDER BY timestamp DESC";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setInt(1, accountId);
            pstmt.setInt(2, accountId);
            ResultSet rs = pstmt.executeQuery();

            System.out.println("\\n--- Transaction History for Acc " + accountId + " ---");
            boolean found = false;
            while (rs.next()) {
                found = true;
                System.out.printf("[%s] %s | Amount: INR %.2f | Charges: INR %.2f | From: %d | To: %d | Note: %s%n",
                        rs.getString("timestamp"),
                        rs.getString("type"),
                        rs.getDouble("amount"),
                        rs.getDouble("charges"),
                        rs.getInt("from_account"),
                        rs.getInt("to_account"),
                        rs.getString("note"));
            }
            if (!found) {
                System.out.println("No transactions found.");
            }
        } catch (SQLException e) {
            System.err.println("Error fetching history: " + e.getMessage());
        }
    }

    public void calculateSavingsInterest(double principal, double annualRate, double years) {
        if (principal <= 0 || annualRate <= 0 || years <= 0) {
            System.out.println("Principal, rate, and time must be greater than zero.");
            return;
        }

        double simpleInterest = (principal * annualRate * years) / 100.0;
        double maturity = principal + simpleInterest;

        System.out.println("\\n--- Savings Interest Estimation ---");
        System.out.printf("Principal: INR %.2f%n", principal);
        System.out.printf("Annual Rate: %.2f%%%n", annualRate);
        System.out.printf("Time: %.2f years%n", years);
        System.out.printf("Interest Earned: INR %.2f%n", simpleInterest);
        System.out.printf("Estimated Maturity Amount: INR %.2f%n", maturity);
    }

    public void createFixedDeposit(int userId, int sourceAccountId, double principal, double annualRate, int years) {
        if (principal <= 0 || annualRate <= 0 || years <= 0) {
            System.out.println("Invalid FD values.");
            return;
        }

        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);

            if (getBalance(conn, sourceAccountId) < principal) {
                System.out.println("Insufficient balance to create FD.");
                return;
            }

            double maturityAmount = principal * Math.pow(1 + (annualRate / 100.0), years);

            updateBalance(conn, sourceAccountId, -principal);

            try (PreparedStatement pstmt = conn.prepareStatement(
                    "INSERT INTO FixedDeposits (user_id, source_account_id, principal, annual_rate, years, maturity_amount) VALUES (?, ?, ?, ?, ?, ?)")) {
                pstmt.setInt(1, userId);
                pstmt.setInt(2, sourceAccountId);
                pstmt.setDouble(3, principal);
                pstmt.setDouble(4, annualRate);
                pstmt.setInt(5, years);
                pstmt.setDouble(6, maturityAmount);
                pstmt.executeUpdate();
            }

            logTransaction(conn, sourceAccountId, 0, "FD_CREATE", principal, 0.0, "Fixed Deposit created");
            conn.commit();

            System.out.printf("FD created successfully. Maturity Amount after %d year(s): INR %.2f%n", years, maturityAmount);
        } catch (SQLException e) {
            System.err.println("FD creation failed: " + e.getMessage());
        }
    }

    public void viewMyFixedDeposits(int userId) {
        String query = "SELECT * FROM FixedDeposits WHERE user_id = ? ORDER BY fd_id DESC";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setInt(1, userId);
            ResultSet rs = pstmt.executeQuery();

            System.out.println("\\n--- Your Fixed Deposits ---");
            boolean found = false;
            while (rs.next()) {
                found = true;
                System.out.printf("FD ID: %d | Source Acc: %d | Principal: INR %.2f | Rate: %.2f%% | Years: %d | Maturity: INR %.2f | Status: %s%n",
                        rs.getInt("fd_id"),
                        rs.getInt("source_account_id"),
                        rs.getDouble("principal"),
                        rs.getDouble("annual_rate"),
                        rs.getInt("years"),
                        rs.getDouble("maturity_amount"),
                        rs.getString("status"));
            }
            if (!found) {
                System.out.println("No fixed deposits found.");
            }
        } catch (SQLException e) {
            System.err.println("Error fetching FD list: " + e.getMessage());
        }
    }

    public void closeFixedDeposit(int userId, int fdId) {
        String selectQuery = "SELECT * FROM FixedDeposits WHERE fd_id = ? AND user_id = ? AND status = 'ACTIVE'";
        String updateFdQuery = "UPDATE FixedDeposits SET status = 'CLOSED' WHERE fd_id = ?";
        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);

            try (PreparedStatement pstmt = conn.prepareStatement(selectQuery)) {
                pstmt.setInt(1, fdId);
                pstmt.setInt(2, userId);
                ResultSet rs = pstmt.executeQuery();

                if (!rs.next()) {
                    System.out.println("Active FD not found.");
                    return;
                }

                int sourceAccountId = rs.getInt("source_account_id");
                double maturityAmount = rs.getDouble("maturity_amount");

                updateBalance(conn, sourceAccountId, maturityAmount);

                try (PreparedStatement updateFd = conn.prepareStatement(updateFdQuery)) {
                    updateFd.setInt(1, fdId);
                    updateFd.executeUpdate();
                }

                logTransaction(conn, 0, sourceAccountId, "FD_CLOSE", maturityAmount, 0.0, "FD maturity credited");
                conn.commit();
                System.out.printf("FD closed successfully. INR %.2f credited to account %d%n", maturityAmount, sourceAccountId);
            }
        } catch (SQLException e) {
            System.err.println("FD closure failed: " + e.getMessage());
        }
    }

    public void calculateLoanEMI(double principal, double annualRate, int years) {
        if (principal <= 0 || annualRate <= 0 || years <= 0) {
            System.out.println("Invalid loan values.");
            return;
        }

        int months = years * 12;
        double monthlyRate = annualRate / (12 * 100.0);
        double emi = (principal * monthlyRate * Math.pow(1 + monthlyRate, months)) /
                (Math.pow(1 + monthlyRate, months) - 1);
        double totalPayable = emi * months;
        double totalInterest = totalPayable - principal;

        System.out.println("\\n--- Loan EMI Calculator ---");
        System.out.printf("Principal: INR %.2f%n", principal);
        System.out.printf("Annual Interest Rate: %.2f%%%n", annualRate);
        System.out.printf("Duration: %d year(s)%n", years);
        System.out.printf("Monthly EMI: INR %.2f%n", emi);
        System.out.printf("Total Payable: INR %.2f%n", totalPayable);
        System.out.printf("Total Interest: INR %.2f%n", totalInterest);
    }

    public void applyLoan(int userId, int accountId, double principal, double annualRate, int years) {
        if (principal <= 0 || annualRate <= 0 || years <= 0) {
            System.out.println("Invalid loan values.");
            return;
        }

        try (Connection conn = DatabaseManager.getConnection()) {
            conn.setAutoCommit(false);

            int months = years * 12;
            double monthlyRate = annualRate / (12 * 100.0);
            double emi = (principal * monthlyRate * Math.pow(1 + monthlyRate, months)) /
                    (Math.pow(1 + monthlyRate, months) - 1);
            double totalPayable = emi * months;

            try (PreparedStatement pstmt = conn.prepareStatement(
                    "INSERT INTO Loans (user_id, account_id, principal, annual_rate, years, emi, total_payable) VALUES (?, ?, ?, ?, ?, ?, ?)")) {
                pstmt.setInt(1, userId);
                pstmt.setInt(2, accountId);
                pstmt.setDouble(3, principal);
                pstmt.setDouble(4, annualRate);
                pstmt.setInt(5, years);
                pstmt.setDouble(6, emi);
                pstmt.setDouble(7, totalPayable);
                pstmt.executeUpdate();
            }

            updateBalance(conn, accountId, principal);
            logTransaction(conn, 0, accountId, "LOAN_CREDIT", principal, 0.0, "Loan credited to account");
            conn.commit();

            System.out.printf("Loan approved and amount credited. EMI: INR %.2f per month%n", emi);
        } catch (SQLException e) {
            System.err.println("Loan processing failed: " + e.getMessage());
        }
    }

    public void viewMyLoans(int userId) {
        String query = "SELECT * FROM Loans WHERE user_id = ? ORDER BY loan_id DESC";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setInt(1, userId);
            ResultSet rs = pstmt.executeQuery();

            System.out.println("\\n--- Your Loans ---");
            boolean found = false;
            while (rs.next()) {
                found = true;
                System.out.printf("Loan ID: %d | Acc ID: %d | Principal: INR %.2f | Rate: %.2f%% | Years: %d | EMI: INR %.2f | Total Payable: INR %.2f | Status: %s%n",
                        rs.getInt("loan_id"),
                        rs.getInt("account_id"),
                        rs.getDouble("principal"),
                        rs.getDouble("annual_rate"),
                        rs.getInt("years"),
                        rs.getDouble("emi"),
                        rs.getDouble("total_payable"),
                        rs.getString("status"));
            }
            if (!found) {
                System.out.println("No loans found.");
            }
        } catch (SQLException e) {
            System.err.println("Error fetching loans: " + e.getMessage());
        }
    }

    public void viewAllUsers() {
        String query = "SELECT id, name, role FROM Users ORDER BY id";
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            System.out.println("\\n--- All Users ---");
            while (rs.next()) {
                System.out.printf("ID: %d | Name: %s | Role: %s%n",
                        rs.getInt("id"),
                        rs.getString("name"),
                        rs.getString("role"));
            }
        } catch (SQLException e) {
            System.err.println("Error fetching users: " + e.getMessage());
        }
    }

    public void viewAllAccounts() {
        String query = "SELECT account_id, user_id, type, balance FROM Accounts ORDER BY account_id";
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            System.out.println("\\n--- All Accounts ---");
            while (rs.next()) {
                System.out.printf("Acc ID: %d | User ID: %d | Type: %s | Balance: INR %.2f%n",
                        rs.getInt("account_id"),
                        rs.getInt("user_id"),
                        rs.getString("type"),
                        rs.getDouble("balance"));
            }
        } catch (SQLException e) {
            System.err.println("Error fetching accounts: " + e.getMessage());
        }
    }

    public void viewAllFixedDeposits() {
        String query = "SELECT * FROM FixedDeposits ORDER BY fd_id DESC";
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            System.out.println("\\n--- All Fixed Deposits ---");
            boolean found = false;
            while (rs.next()) {
                found = true;
                System.out.printf("FD ID: %d | User ID: %d | Principal: INR %.2f | Rate: %.2f%% | Years: %d | Maturity: INR %.2f | Status: %s%n",
                        rs.getInt("fd_id"),
                        rs.getInt("user_id"),
                        rs.getDouble("principal"),
                        rs.getDouble("annual_rate"),
                        rs.getInt("years"),
                        rs.getDouble("maturity_amount"),
                        rs.getString("status"));
            }
            if (!found) {
                System.out.println("No fixed deposits found.");
            }
        } catch (SQLException e) {
            System.err.println("Error fetching all FDs: " + e.getMessage());
        }
    }

    public void viewAllLoans() {
        String query = "SELECT * FROM Loans ORDER BY loan_id DESC";
        try (Connection conn = DatabaseManager.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            System.out.println("\\n--- All Loans ---");
            boolean found = false;
            while (rs.next()) {
                found = true;
                System.out.printf("Loan ID: %d | User ID: %d | Principal: INR %.2f | EMI: INR %.2f | Total Payable: INR %.2f | Status: %s%n",
                        rs.getInt("loan_id"),
                        rs.getInt("user_id"),
                        rs.getDouble("principal"),
                        rs.getDouble("emi"),
                        rs.getDouble("total_payable"),
                        rs.getString("status"));
            }
            if (!found) {
                System.out.println("No loans found.");
            }
        } catch (SQLException e) {
            System.err.println("Error fetching all loans: " + e.getMessage());
        }
    }

    public void deleteUser(int userId) {
        String query = "DELETE FROM Users WHERE id = ? AND role != 'Admin'";
        try (Connection conn = DatabaseManager.getConnection();
             PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setInt(1, userId);
            int affected = pstmt.executeUpdate();
            if (affected > 0) {
                System.out.println("User deleted successfully.");
            } else {
                System.out.println("User not found or cannot delete an Admin.");
            }
        } catch (SQLException e) {
            System.err.println("Delete failed: " + e.getMessage());
        }
    }

    private double getBalance(Connection conn, int accountId) throws SQLException {
        String query = "SELECT balance FROM Accounts WHERE account_id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setInt(1, accountId);
            ResultSet rs = pstmt.executeQuery();
            if (rs.next()) {
                return rs.getDouble("balance");
            }
            throw new SQLException("Account not found.");
        }
    }

    private void updateBalance(Connection conn, int accountId, double amount) throws SQLException {
        String query = "UPDATE Accounts SET balance = balance + ? WHERE account_id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setDouble(1, amount);
            pstmt.setInt(2, accountId);
            int affected = pstmt.executeUpdate();
            if (affected == 0) {
                throw new SQLException("Account not found.");
            }
        }
    }

    private boolean accountExists(Connection conn, int accountId) throws SQLException {
        String query = "SELECT 1 FROM Accounts WHERE account_id = ?";
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setInt(1, accountId);
            return pstmt.executeQuery().next();
        }
    }

    private void logTransaction(Connection conn, int from, int to, String type, double amount, double charges, String note) throws SQLException {
        String query = "INSERT INTO Transactions (from_account, to_account, type, amount, charges, note) VALUES (?, ?, ?, ?, ?, ?)";
        try (PreparedStatement pstmt = conn.prepareStatement(query)) {
            pstmt.setInt(1, from);
            pstmt.setInt(2, to);
            pstmt.setString(3, type);
            pstmt.setDouble(4, amount);
            pstmt.setDouble(5, charges);
            pstmt.setString(6, note);
            pstmt.executeUpdate();
        }
    }
}

// ==========================================
// MAIN APPLICATION
// ==========================================

public class BankingSystem {
    private static final Scanner scanner = new Scanner(System.in);
    private static final AuthService authService = new AuthService();
    private static final BankService bankService = new BankService();
    private static User currentUser = null;

    public static void main(String[] args) {
        DatabaseManager.initializeDatabase();
        System.out.println("=== Welcome to the Advanced Java Banking System ===");

        while (true) {
            if (currentUser == null) {
                showMainMenu();
            } else if (currentUser.role.equalsIgnoreCase("Admin")) {
                showAdminMenu();
            } else {
                showCustomerMenu();
            }
        }
    }

    private static void showMainMenu() {
        System.out.println("\\n1. Login");
        System.out.println("2. Register Customer");
        System.out.println("3. Exit");
        System.out.print("Choose an option: ");
        String choice = scanner.nextLine();

        switch (choice) {
            case "1":
                System.out.print("Username: ");
                String name = scanner.nextLine();
                System.out.print("Password: ");
                String pass = scanner.nextLine();
                currentUser = authService.login(name, pass);
                if (currentUser == null) {
                    System.out.println("Invalid credentials.");
                } else {
                    System.out.println("Welcome, " + currentUser.name + "!");
                }
                break;
            case "2":
                System.out.print("Enter New Username: ");
                String newName = scanner.nextLine();
                System.out.print("Enter Password: ");
                String newPass = scanner.nextLine();
                if (authService.register(newName, newPass, "Customer")) {
                    System.out.println("Registration successful. You can now login.");
                }
                break;
            case "3":
                System.out.println("Exiting System. Goodbye!");
                System.exit(0);
                break;
            default:
                System.out.println("Invalid option.");
        }
    }

    private static void showAdminMenu() {
        System.out.println("\\n--- Admin Panel ---");
        System.out.println("1. View All Users");
        System.out.println("2. View All Accounts");
        System.out.println("3. View All Fixed Deposits");
        System.out.println("4. View All Loans");
        System.out.println("5. Delete User");
        System.out.println("6. Logout");
        System.out.print("Choose: ");
        String choice = scanner.nextLine();

        try {
            switch (choice) {
                case "1":
                    bankService.viewAllUsers();
                    break;
                case "2":
                    bankService.viewAllAccounts();
                    break;
                case "3":
                    bankService.viewAllFixedDeposits();
                    break;
                case "4":
                    bankService.viewAllLoans();
                    break;
                case "5":
                    System.out.print("Enter User ID to delete: ");
                    int id = Integer.parseInt(scanner.nextLine());
                    bankService.deleteUser(id);
                    break;
                case "6":
                    currentUser = null;
                    System.out.println("Logged out.");
                    break;
                default:
                    System.out.println("Invalid option.");
            }
        } catch (NumberFormatException e) {
            System.out.println("Invalid number format.");
        }
    }

    private static void showCustomerMenu() {
        System.out.println("\\n--- Customer Panel ---");
        System.out.println("1. Create Account (Savings/Current)");
        System.out.println("2. View Accounts & Balance");
        System.out.println("3. Deposit Money");
        System.out.println("4. Withdraw Money");
        System.out.println("5. Transfer Money");
        System.out.println("6. View Transaction History");
        System.out.println("7. Calculate Savings Interest by Time");
        System.out.println("8. Create Fixed Deposit");
        System.out.println("9. View My Fixed Deposits");
        System.out.println("10. Close Fixed Deposit");
        System.out.println("11. Loan EMI Calculator");
        System.out.println("12. Apply Loan");
        System.out.println("13. View My Loans");
        System.out.println("14. Logout");
        System.out.print("Choose: ");
        String choice = scanner.nextLine();

        try {
            switch (choice) {
                case "1":
                    System.out.print("Account Type (Savings/Current): ");
                    String type = scanner.nextLine();
                    if (type.equalsIgnoreCase("Savings") || type.equalsIgnoreCase("Current")) {
                        bankService.createAccount(currentUser.id, type);
                    } else {
                        System.out.println("Invalid type. Must be Savings or Current.");
                    }
                    break;
                case "2":
                    bankService.viewBalance(currentUser.id);
                    break;
                case "3":
                    System.out.print("Enter Account ID to deposit into: ");
                    int depAcc = Integer.parseInt(scanner.nextLine());
                    System.out.print("Enter Amount: ");
                    double depAmt = Double.parseDouble(scanner.nextLine());
                    bankService.depositMoney(depAcc, depAmt);
                    break;
                case "4":
                    System.out.print("Enter Account ID to withdraw from: ");
                    int withAcc = Integer.parseInt(scanner.nextLine());
                    System.out.print("Enter Amount: ");
                    double withAmt = Double.parseDouble(scanner.nextLine());
                    bankService.withdrawMoney(withAcc, withAmt);
                    break;
                case "5":
                    System.out.print("Enter Your Account ID: ");
                    int fromAcc = Integer.parseInt(scanner.nextLine());
                    System.out.print("Enter Destination Account ID: ");
                    int toAcc = Integer.parseInt(scanner.nextLine());
                    System.out.print("Enter Amount: ");
                    double transAmt = Double.parseDouble(scanner.nextLine());
                    bankService.transferMoney(fromAcc, toAcc, transAmt);
                    break;
                case "6":
                    System.out.print("Enter Account ID to view history: ");
                    int histAcc = Integer.parseInt(scanner.nextLine());
                    bankService.viewTransactionHistory(histAcc);
                    break;
                case "7":
                    System.out.print("Enter Principal Amount: ");
                    double principal = Double.parseDouble(scanner.nextLine());
                    System.out.print("Enter Annual Interest Rate (%): ");
                    double rate = Double.parseDouble(scanner.nextLine());
                    System.out.print("Enter Time (in years): ");
                    double years = Double.parseDouble(scanner.nextLine());
                    bankService.calculateSavingsInterest(principal, rate, years);
                    break;
                case "8":
                    System.out.print("Enter Source Account ID: ");
                    int fdAcc = Integer.parseInt(scanner.nextLine());
                    System.out.print("Enter FD Principal Amount: ");
                    double fdPrincipal = Double.parseDouble(scanner.nextLine());
                    System.out.print("Enter Annual FD Rate (%): ");
                    double fdRate = Double.parseDouble(scanner.nextLine());
                    System.out.print("Enter FD Duration (years): ");
                    int fdYears = Integer.parseInt(scanner.nextLine());
                    bankService.createFixedDeposit(currentUser.id, fdAcc, fdPrincipal, fdRate, fdYears);
                    break;
                case "9":
                    bankService.viewMyFixedDeposits(currentUser.id);
                    break;
                case "10":
                    System.out.print("Enter FD ID to close: ");
                    int fdId = Integer.parseInt(scanner.nextLine());
                    bankService.closeFixedDeposit(currentUser.id, fdId);
                    break;
                case "11":
                    System.out.print("Enter Loan Principal: ");
                    double loanPrincipal = Double.parseDouble(scanner.nextLine());
                    System.out.print("Enter Annual Interest Rate (%): ");
                    double loanRate = Double.parseDouble(scanner.nextLine());
                    System.out.print("Enter Loan Duration (years): ");
                    int loanYears = Integer.parseInt(scanner.nextLine());
                    bankService.calculateLoanEMI(loanPrincipal, loanRate, loanYears);
                    break;
                case "12":
                    System.out.print("Enter Account ID to receive loan amount: ");
                    int loanAcc = Integer.parseInt(scanner.nextLine());
                    System.out.print("Enter Loan Principal: ");
                    double applyPrincipal = Double.parseDouble(scanner.nextLine());
                    System.out.print("Enter Annual Interest Rate (%): ");
                    double applyRate = Double.parseDouble(scanner.nextLine());
                    System.out.print("Enter Loan Duration (years): ");
                    int applyYears = Integer.parseInt(scanner.nextLine());
                    bankService.applyLoan(currentUser.id, loanAcc, applyPrincipal, applyRate, applyYears);
                    break;
                case "13":
                    bankService.viewMyLoans(currentUser.id);
                    break;
                case "14":
                    currentUser = null;
                    System.out.println("Logged out.");
                    break;
                default:
                    System.out.println("Invalid option.");
            }
        } catch (NumberFormatException e) {
            System.out.println("Error: Please enter valid numeric values.");
        } catch (Exception e) {
            System.out.println("An unexpected error occurred: " + e.getMessage());
        }
    }
}