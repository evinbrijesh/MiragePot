#!/usr/bin/env bash

# Simple helper script to run MiragePot backend and dashboard.

set -e

# Start backend server
python backend/server.py &
BACKEND_PID=$!

echo "[+] Backend started with PID $BACKEND_PID"

echo "[+] Starting Streamlit dashboard..."
streamlit run dashboard/app.py

# When dashboard exits, stop backend
kill "$BACKEND_PID" 2>/dev/null || true
