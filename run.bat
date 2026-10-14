@echo off
REM Windows launcher: creates venv on first run, then starts NetScope.
if not exist .venv ( python -m venv .venv )
call .venv\Scripts\activate
pip install -q -r requirements.txt
REM Optional login: set NETSCOPE_PASSWORD=your_password
streamlit run app.py
