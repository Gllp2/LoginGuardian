import sys
import os
from getpass import getpass
import base64
import secrets
import hashlib

USERS_FILE = "projeto_final_login_000086/users_secure.json"
DEFAULT_ITERATIONS = 200_000
DKLEN = 32

def _hash_password(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    pwd_bytes = password.encode("utf-8")
    try:
        dk = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, iterations, dklen=DKLEN)
        return dk
    finally:
        pwd_bytes = b"\x00" * len(pwd_bytes)

def _load_users() -> dict:
    import json
    if not os.path.exists(USERS_FILE):
        return {}
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def _save_users(users: dict) -> None:
    import json
    temp = USERS_FILE + ".tmp"
    with open(temp, "w", encoding="utf-8") as f:
        json.dump(users, f, ensure_ascii=False, indent=2)
    os.replace(temp, USERS_FILE)

def create_user():
    users = _load_users()
    username = input("Username: ").strip()
    if not username:
        print("Username inválido.")
        return
    if username in users:
        print("Utilizador já existe.")
        return

    pwd = getpass("Password: ")
    pwd2 = getpass("Confirmar: ")
    if pwd != pwd2:
        print("Passwords não coincidem.")
        return
    if len(pwd) < 5:
        print("Password mínimo 5 caracteres.")
        return

    salt = secrets.token_bytes(16)
    iterations = DEFAULT_ITERATIONS
    dk = _hash_password(pwd, salt, iterations)

    users[username] = {
        "salt": base64.b64encode(salt).decode("utf-8"),
        "hash": base64.b64encode(dk).decode("utf-8"),
        "iterations": iterations
    }
    _save_users(users)
    print(f"✓ Utilizador '{username}' criado.")

if __name__ == "__main__":
    create_user()
