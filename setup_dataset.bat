@echo off
REM setup_datasets.bat
REM Windows Batch Script to Download WAF Datasets

echo ======================================================================
echo WAF DATASETS SETUP (Windows Batch Version)
echo ======================================================================
echo.
echo This script will download the following datasets:
echo   1. SecLists (50MB) - Attack payloads
echo   2. OWASP Core Rule Set (5MB) - ModSecurity rules
echo   3. PayloadsAllTheThings (100MB) - Exploitation payloads
echo.
echo Total download size: ~155MB
echo.

set /p confirm="Continue with download? (y/n): "
if /i not "%confirm%"=="y" (
    echo Setup cancelled.
    pause
    exit /b
)

REM Create datasets directory
echo.
echo Creating datasets directory...
if not exist "datasets" mkdir datasets
cd datasets

REM Clone SecLists
echo.
echo ======================================================================
echo Downloading SecLists...
echo ======================================================================
if exist "SecLists" (
    echo SecLists already exists. Updating...
    cd SecLists
    git pull
    cd ..
) else (
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git
)
echo ✓ SecLists ready

REM Clone OWASP CRS
echo.
echo ======================================================================
echo Downloading OWASP Core Rule Set...
echo ======================================================================
if exist "coreruleset" (
    echo OWASP CRS already exists. Updating...
    cd coreruleset
    git pull
    cd ..
) else (
    git clone --depth 1 https://github.com/coreruleset/coreruleset.git
)
echo ✓ OWASP CRS ready

REM Clone PayloadsAllTheThings
echo.
echo ======================================================================
echo Downloading PayloadsAllTheThings...
echo ======================================================================
if exist "PayloadsAllTheThings" (
    echo PayloadsAllTheThings already exists. Updating...
    cd PayloadsAllTheThings
    git pull
    cd ..
) else (
    git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git
)
echo ✓ PayloadsAllTheThings ready

REM Create CSIC dataset directory
echo.
echo ======================================================================
echo Setting up CSIC 2010 dataset directory...
echo ======================================================================
if not exist "csic2010" mkdir csic2010
echo ✓ Directory created: datasets\csic2010\

cd ..

REM Display file structure
echo.
echo ======================================================================
echo DATASET STRUCTURE
echo ======================================================================
echo.
echo datasets\
echo ├── SecLists\              ✓ Ready
echo │   ├── Fuzzing\
echo │   │   ├── SQLi\
echo │   │   ├── XSS\
echo │   │   └── command-injection-commix.txt
echo │   └── ...
echo ├── coreruleset\           ✓ Ready
echo │   └── rules\
echo │       ├── REQUEST-941-APPLICATION-ATTACK-XSS.conf
echo │       ├── REQUEST-942-APPLICATION-ATTACK-SQLI.conf
echo │       └── ...
echo ├── PayloadsAllTheThings\  ✓ Ready
echo │   ├── SQL Injection\
echo │   ├── XSS Injection\
echo │   └── ...
echo └── csic2010\              ⚠  Manual download required
echo     └── CSIC_2010.csv           (download needed)
echo.

REM CSIC dataset instructions
echo ======================================================================
echo ⚠  MANUAL STEP REQUIRED: CSIC 2010 DATASET
echo ======================================================================
echo.
echo The CSIC 2010 dataset must be downloaded manually:
echo.
echo 1. Visit: https://www.kaggle.com/datasets/syedsaqlainhussain/http-csic-2010-dataset
echo 2. Download: CSIC_2010.csv
echo 3. Place it in: datasets\csic2010\CSIC_2010.csv
echo 4. Run: python convert_csic_csv_fixed.py
echo.

REM Generate enhanced rules
echo ======================================================================
echo GENERATING ENHANCED RULES
echo ======================================================================
echo.

if exist "enhanced_rules_generator.py" (
    echo Running enhanced_rules_generator.py...
    python enhanced_rules_generator.py
    
    if exist "rules_enhanced.py" (
        echo.
        echo ✓ rules_enhanced.py generated successfully!
    ) else (
        echo.
        echo ⚠ Failed to generate rules_enhanced.py
        echo   You can run it manually: python enhanced_rules_generator.py
    )
) else (
    echo ⚠ enhanced_rules_generator.py not found
    echo   Skipping rule generation
)

REM Final summary
echo.
echo ======================================================================
echo ✓ SETUP COMPLETE!
echo ======================================================================
echo.
echo What's ready:
echo   ✓ SecLists datasets downloaded
echo   ✓ OWASP Core Rule Set downloaded
echo   ✓ PayloadsAllTheThings downloaded
echo.
echo What's next:
echo   1. Download CSIC 2010 CSV from Kaggle (see instructions above)
echo   2. Place it in: datasets\csic2010\CSIC_2010.csv
echo   3. Run: python convert_csic_csv_fixed.py
echo   4. Run: python train_anomaly_detection.py
echo   5. Replace rules.py with rules_enhanced.py in your project
echo   6. Restart your WAF application
echo.
echo For help: See WINDOWS_SETUP_GUIDE.md
echo.

pause