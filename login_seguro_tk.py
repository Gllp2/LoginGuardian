import json
import os
import sys
import time
import base64
import secrets
import hashlib
import hmac
import csv
import socket
from datetime import datetime
from getpass import getpass
import tkinter as tk
from tkinter import messagebox

from utils import registar_tentativa_login, carregar_blacklist, ip_bloqueado, atualizar_blacklist

USERS_FILE = "projeto_final_login_000086/users_secure.json"
DEFAULT_ITERATIONS = 200_000
DKLEN = 32
MAX_ATTEMPTS = 5
BASE_LOCK_SECONDS = 30

_failed_attempts = {}

def obter_ip_cliente() -> str:
    """Obtém o IP do cliente."""
    try:
        hostname = socket.gethostname()
        ip_local = socket.gethostbyname(hostname)
        return ip_local
    except:
        return "127.0.0.1"

def _load_users() -> dict:
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def _save_users(users: dict) -> None:
    temp = USERS_FILE + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)
    os.replace(temp, USERS_FILE)

def _hash_password(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    pwd_bytes = password.encode("utf-8")
    try:
        dk = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, iterations, dklen=DKLEN)
        return dk
    finally:
        pwd_bytes = b"\x00" * len(pwd_bytes)

def create_user_cli():
    users = _load_users()
    username = input("Username: ").strip()
    if not username or username in users:
        print("Username inválido ou já existe.")
        return

    pwd = getpass("Password: ")
    pwd2 = getpass("Confirmar: ")
    if pwd != pwd2 or len(pwd) < 8:
        print("Passwords não coincidem ou muito curtas (mínimo 8).")
        return

    salt = secrets.token_bytes(16)
    dk = _hash_password(pwd, salt, DEFAULT_ITERATIONS)

    users[username] = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "hash": base64.b64encode(dk).decode("utf-8"),
        "iterations": DEFAULT_ITERATIONS
    }
    _save_users(users)
    print(f"✓ Utilizador '{username}' criado.")

def _is_locked(username: str) -> (bool, int):
    info = _failed_attempts.get(username)
    if not info:
        return False, 0
    lock_until = info.get("lock_until", 0)
    now = time.time()
    if now < lock_until:
        return True, int(lock_until - now)
    return False, 0

def _register_failed_attempt(username: str):
    info = _failed_attempts.setdefault(username, {"count": 0, "lock_until": 0, "lock_count": 0})
    info["count"] += 1
    if info["count"] >= MAX_ATTEMPTS:
        info["lock_count"] = info.get("lock_count", 0) + 1
        lock_time = BASE_LOCK_SECONDS * (2 ** (info["lock_count"] - 1))
        info["lock_until"] = time.time() + lock_time
        info["count"] = 0
    _failed_attempts[username] = info

def _register_success(username: str):
    if username in _failed_attempts:
        del _failed_attempts[username]

def verify_credentials(username: str, password: str) -> bool:
    users = _load_users()

    locked, remaining = _is_locked(username)
    if locked:
        return False

    record = users.get(username)
    if record is None:
        dummy_salt = secrets.token_bytes(16)
        _ = _hash_password("dummy_password", dummy_salt, DEFAULT_ITERATIONS)
        return False

    try:
        salt = base64.b64decode(record["salt"])
        expected_hash = base64.b64decode(record["hash"])
        iterations = int(record.get("iterations", DEFAULT_ITERATIONS))
    except Exception:
        return False

    candidate = _hash_password(password, salt, iterations)
    ok = hmac.compare_digest(candidate, expected_hash)
    candidate = None

    if ok:
        _register_success(username)
        return True
    else:
        _register_failed_attempt(username)
        return False

def launch_gui():
    root = tk.Tk()
    root.title("LogIn")
    root.geometry("420x280")
    root.resizable(False, False)

    frame = tk.Frame(root, padx=12, pady=12)
    frame.pack(expand=True, fill=tk.BOTH)

    lbl = tk.Label(frame, text="LogIn", font=("Segoe UI", 12, "bold"))
    lbl.grid(row=0, column=0, columnspan=2, pady=(0, 10))

    tk.Label(frame, text="Utilizador:").grid(row=1, column=0, sticky="w")
    entry_user = tk.Entry(frame, width=30)
    entry_user.grid(row=1, column=1, pady=4)
    entry_user.focus_set()

    tk.Label(frame, text="Palavra-passe:").grid(row=2, column=0, sticky="w")
    entry_pwd = tk.Entry(frame, width=30, show="*")
    entry_pwd.grid(row=2, column=1, pady=4)

    def on_login(event=None):
        user = entry_user.get().strip()
        pwd = entry_pwd.get()
        
        if not user or not pwd:
            messagebox.showwarning("Aviso", "Preencha utilizador e palavra-passe.")
            return

        ip = obter_ip_cliente()
        
        if ip_bloqueado(ip):
            registar_tentativa_login(user, ip, False)
            messagebox.showerror("Acesso Bloqueado", 
                f"IP {ip} está em blacklist.\nContacte administrador.")
            status_var.set("Acesso bloqueado por IP em blacklist.")
            entry_pwd.delete(0, tk.END)
            return

        locked, seconds = _is_locked(user)
        if locked:
            registar_tentativa_login(user, ip, False)
            messagebox.showerror("Bloqueado", 
                f"Conta bloqueada. Tente em {seconds}s.")
            status_var.set(f"Conta bloqueada por {seconds}s.")
            entry_pwd.delete(0, tk.END)
            return

        ok = verify_credentials(user, pwd)
        registar_tentativa_login(user, ip, ok)

        entry_pwd.delete(0, tk.END)
        pwd = None

        if ok:
            status_var.set(f"✓ Login bem-sucedido. Bem-vindo/a, {user}.")
            messagebox.showinfo("Sucesso", 
                f"Login bem-sucedido!\nBem-vindo/a, {user}.\n\n(IP: {ip})")
        else:
            locked2, sec2 = _is_locked(user)
            if locked2:
                messagebox.showerror("Bloqueado", 
                    f"Conta bloqueada por {sec2}s.")
                status_var.set(f"Conta bloqueada por {sec2}s.")
            else:
                messagebox.showerror("Erro", "Credenciais inválidas.")
                status_var.set("Credenciais inválidas.")

    def on_analise():
        try:
            atualizar_blacklist(limite_falhas=3)
            from utils import carregar_blacklist
            blacklist = carregar_blacklist()
            
            msg = f"Blacklist atualizada\n"
            msg += f"IPs bloqueados: {blacklist['total_ips_bloqueados']}\n"
            msg += f"IPs: {', '.join(blacklist['ips_bloqueados']) if blacklist['ips_bloqueados'] else 'nenhum'}"
            
            messagebox.showinfo("Análise de Logs", msg)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao analisar: {e}")

    btn_login = tk.Button(frame, text="Login", width=14, command=on_login)
    btn_login.grid(row=3, column=0, pady=12, sticky="ew")

    btn_analisar = tk.Button(frame, text="Analisar Logs", width=14, command=on_analise)
    btn_analisar.grid(row=3, column=1, pady=12, sticky="ew")

    tk.Label(frame, text="").grid(row=4, columnspan=2)

    btn_quit = tk.Button(frame, text="Sair", width=14, command=root.destroy)
    btn_quit.grid(row=5, column=0, columnspan=2, sticky="ew")

    root.bind("<Return>", on_login)

    root.mainloop()

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--create-user":
        create_user_cli()
        sys.exit(0)
    else:
        launch_gui()
