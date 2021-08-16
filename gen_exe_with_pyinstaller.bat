python updateRequirements.py
pyinstaller --distpath dist_exe --onefile AS4PGC.spec
rd /S /Q build
rd /S /Q __pycache__
xcopy /y "config.ini" "dist_exe/config.ini"
pause
