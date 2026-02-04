# utils.py
import csv
import json
import os
from datetime import datetime
from parser import detetar_formato, parse_linhas
from analytics import contar_falhas_por_ip, ips_suspeitos

LOGS_FILE = "projeto_final_login_000086/logs_exemplo.csv"
BLACKLIST_FILE = "projeto_final_login_000086/blacklist.json"

def ler_ficheiro(path: str) -> list[str]:
    """Lê um ficheiro de texto e devolve uma lista de linhas."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().splitlines()
    except FileNotFoundError:
        return []
    except Exception:
        return []

def registar_tentativa_login(utilizador: str, ip: str, sucesso: bool) -> None:
    """Regista uma tentativa de login no ficheiro CSV."""
    timestamp = datetime.now().isoformat() + "Z"
    nova_linha = [timestamp, utilizador, ip, str(sucesso).lower()]
    
    try:
        ficheiro_existe = os.path.exists(LOGS_FILE)
        with open(LOGS_FILE, "a", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            if not ficheiro_existe:
                writer.writerow(["timestamp", "utilizador", "ip", "sucesso"])
            writer.writerow(nova_linha)
    except Exception:
        pass

def gerar_blacklist(limite_falhas: int = 3) -> dict:
    """Gera blacklist a partir dos logs."""
    linhas = ler_ficheiro(LOGS_FILE)
    if not linhas:
        return {
            "generated_at": datetime.now().isoformat(),
            "limite_falhas": limite_falhas,
            "ips_bloqueados": [],
            "total_ips_bloqueados": 0
        }
    
    formato = detetar_formato(linhas)
    registos = parse_linhas(linhas, formato)
    
    if not registos:
        return {
            "generated_at": datetime.now().isoformat(),
            "limite_falhas": limite_falhas,
            "ips_bloqueados": [],
            "total_ips_bloqueados": 0
        }
    
    contagens = contar_falhas_por_ip(registos)
    suspeitos = ips_suspeitos(contagens, limite=limite_falhas)
    
    return {
        "generated_at": datetime.now().isoformat(),
        "limite_falhas": limite_falhas,
        "ips_bloqueados": sorted(suspeitos),
        "total_ips_bloqueados": len(suspeitos)
    }

def salvar_blacklist(blacklist: dict) -> None:
    """Guarda a blacklist em ficheiro JSON."""
    try:
        with open(BLACKLIST_FILE, "w", encoding="utf-8") as f:
            json.dump(blacklist, f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def carregar_blacklist() -> dict:
    """Carrega a blacklist do ficheiro."""
    if not os.path.exists(BLACKLIST_FILE):
        return {"generated_at": None, "limite_falhas": 3, "ips_bloqueados": [], "total_ips_bloqueados": 0}
    
    try:
        with open(BLACKLIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"generated_at": None, "limite_falhas": 3, "ips_bloqueados": [], "total_ips_bloqueados": 0}

def ip_bloqueado(ip: str) -> bool:
    """Verifica se um IP está na blacklist."""
    blacklist = carregar_blacklist()
    return ip in blacklist.get("ips_bloqueados", [])

def atualizar_blacklist(limite_falhas: int = 3) -> None:
    """Atualiza a blacklist."""
    blacklist = gerar_blacklist(limite_falhas)
    salvar_blacklist(blacklist)
