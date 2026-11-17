@echo off
setlocal
cd /d "%~dp0"

echo ===================================================
echo   Sentinel Audit - Firebase Cloud Setup & Deploy
echo   Target Project: sentinel-audit-cae96
echo ===================================================
echo.

echo [1/3] Checking Firebase login...
call npx --yes firebase-tools login
if errorlevel 1 (
    echo [ERROR] Firebase login failed.
    pause
    exit /b 1
)

echo.
echo [2/3] Deploying Firestore Database Rules to sentinel-audit-cae96...
call npx --yes firebase-tools deploy --only firestore --project sentinel-audit-cae96
if errorlevel 1 (
    echo [WARNING] Firestore rules deployment encountered an issue. Ensure Firestore is created in Firebase Console.
)

echo.
echo [3/3] Deployment options:
echo.
echo  A) If you want to set your public Cloud server URL in Firebase Firestore
echo     so your Android mobile app connects to it automatically:
echo.
set /p CLOUD_URL="Enter your server URL (or press Enter to skip): "
if not "%CLOUD_URL%"=="" (
    python -m security_audit.firebase_sync --set-url "%CLOUD_URL%" --project sentinel-audit-cae96
    echo [OK] Cloud URL saved to Firebase Firestore! Mobile app will discover it automatically.
)

echo.
echo Setup completed!
pause
