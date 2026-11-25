@echo off
cd /d "C:\Users\sandr\OneDrive\Documents\Default Project\sentinelx"
"C:\Users\sandr\AppData\Local\Programs\Python\Python312\python.exe" -m uvicorn app.main:app --host 0.0.0.0 --port 8000 >> "C:\Users\sandr\AppData\Local\Temp\opencode\sentinelx-server-task.log" 2>&1
