@echo off
title BharatBank Server
color 0A

echo.
echo  ==============================================
echo     BHARATBANK — आपका विश्वसनीय बैंक
echo  ==============================================
echo.

REM Check if SQLite JDBC jar exists
if not exist "lib\sqlite-jdbc.jar" (
    echo [ERROR] sqlite-jdbc.jar not found in lib\ folder!
    echo.
    echo Please download it from:
    echo https://github.com/xerial/sqlite-jdbc/releases
    echo Download the file named: sqlite-jdbc-x.x.x.jar
    echo Rename it to: sqlite-jdbc.jar
    echo Place it in the lib\ folder
    echo.
    pause
    exit /b 1
)

REM Check if Java is installed
java -version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Java not found! Please install Java JDK 11 or higher.
    echo Download from: https://adoptium.net/
    pause
    exit /b 1
)

REM Check if javac is available
javac -version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] javac not found! Please install Java JDK (not just JRE).
    echo Download from: https://adoptium.net/
    pause
    exit /b 1
)

echo [1/3] Compiling BharatBank...
if not exist "out" mkdir out
javac -cp "lib\sqlite-jdbc.jar" -d out src\BankingSystem.java

if errorlevel 1 (
    echo.
    echo [ERROR] Compilation failed! Check the source code.
    pause
    exit /b 1
)

echo [2/3] Compilation successful!
echo [3/3] Starting BharatBank Server...
echo.
echo  Your bank is starting at: http://localhost:8080
echo  Opening browser in 3 seconds...
echo.
echo  Press Ctrl+C to stop the server
echo.

REM Open browser after a short delay
start "" timeout /t 3 /nobreak >nul & start "" "http://localhost:8080"

REM Run the server
java -cp "out;lib\sqlite-jdbc.jar" BankingSystem

pause
