@echo off
title BharatBank Server
color 0A
echo.
echo  BHARATBANK - Aapka Vishwasniya Bank
echo.
if not exist "lib\sqlite-jdbc.jar" (
    echo ERROR: sqlite-jdbc.jar not found in lib folder!
    pause
    exit /b 1
)
if not exist "out" mkdir out
javac -cp "lib\sqlite-jdbc.jar" -d out src\BankingSystem.java
if errorlevel 1 (
    echo ERROR: Compilation failed!
    pause
    exit /b 1
)
echo Server starting... Open http://localhost:8080 in browser
echo Login: admin / admin123
echo Press Ctrl+C to stop
start "" "http://localhost:8080"
java -cp "out;lib\sqlite-jdbc.jar" BankingSystem
pause
