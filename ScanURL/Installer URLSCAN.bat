@echo off
title Installation des Modules - OsintMx
color 0D

:: Vérifie si Python est installé
set "PYTHON_CMD=python"
%PYTHON_CMD% --version >nul 2>&1

if %errorlevel% neq 0 (
    echo Python n'est pas détecté sur ce système.
    echo Veuillez installer Python depuis https://www.python.org/downloads/
    echo Appuyez sur une touche pour quitter...
    pause >nul
    exit /b
)

:: Installation des modules requis
echo Installation des modules Python nécessaires...
%PYTHON_CMD% -m pip install requests beautifulsoup4 tqdm >nul 2>&1

if %errorlevel% neq 0 (
    echo.
    echo Erreur lors de l'installation des modules. Assurez-vous que pip est configuré correctement.
    echo Appuyez sur une touche pour quitter...
    pause >nul
    exit /b
)

echo.
echo Les modules Python requis ont été installés avec succès. Vous pouvez maintenant lancer OsintMx.
echo Appuyez sur une touche pour terminer...
pause >nul
