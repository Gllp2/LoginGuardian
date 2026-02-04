#LoginGuardian
Lightweight Python login system with secure user storage, blacklist protection, and basic log analytics. ✅

A compact, educational project demonstrating a secure login flow using Python. It includes user creation, secure user storage, blacklist enforcement, a simple Tkinter login GUI, and basic log parsing/analytics for authentication events.

Features 🔧
Secure user management (create_user.py, users_secure.json)
GUI login (login_seguro_tk.py) using Tkinter
Blacklist protection (blacklist.json) to block known bad actors
Log parsing & analytics (analytics.py, logs_exemplo.csv)
⚠️ Requires Python 3.8+ and Tkinter (standard on most systems).

Quick start 🚀
Create or activate a Python environment:
python3 -m venv .venv && source .venv/bin/activate
Create a user:
python3 create_user.py
Run the GUI login:
python3 login_seguro_tk.py
Run simple analytics:
python3 analytics.py logs_exemplo.csv
