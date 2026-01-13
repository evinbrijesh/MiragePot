@echo off
REM Windows helper script to run MiragePot backend and dashboard.

start "MiragePot Backend" cmd /k "python backend\server.py"
start "MiragePot Dashboard" cmd /k "streamlit run dashboard\app.py"
