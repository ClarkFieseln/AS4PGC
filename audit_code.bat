bandit -r as4pgc > audit/bandit_report.txt
REM safety needs internet connection:
safety check -r requirements.txt > audit/safety_report.txt
