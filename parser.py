import csv
import json

def detetar_formato(linhas: list[str]) -> str:
    """Deteta se o ficheiro é CSV, delimitado por pipe (|) ou JSONL."""
    for linha in linhas[:5]:
        if not linha.strip():
            continue
        if "timestamp" in linha and "," in linha:
            return "csv"
        if " | " in linha:
            return "pipe"
        if linha.strip().startswith("{") and linha.strip().endswith("}"):
            return "jsonl"
    return "csv"

def _normalizar(r: dict) -> dict:
    """Normaliza os campos do registo."""
    status = str(r.get("sucesso", "")).lower().strip()
    sucesso = status in ("true", "ok", "1")
    return {
        "timestamp": r.get("timestamp", "").strip(),
        "utilizador": r.get("utilizador", "").strip().lower(),
        "ip": r.get("ip", "").strip(),
        "sucesso": sucesso,
    }

def parse_linhas(linhas: list[str], formato: str) -> list[dict]:
    """Converte as linhas num formato padronizado de dicionários."""
    registos = []
    if formato == "csv":
        reader = csv.DictReader(linhas)
        for row in reader:
            registos.append(_normalizar(row))
    elif formato == "pipe":
        for l in linhas:
            partes = [p.strip() for p in l.split("|")]
            if len(partes) == 4:
                ts, user, ip, status = partes
                registos.append(_normalizar({
                    "timestamp": ts,
                    "utilizador": user,
                    "ip": ip,
                    "sucesso": status
                }))
    elif formato == "jsonl":
        for l in linhas:
            try:
                obj = json.loads(l)
                registos.append(_normalizar(obj))
            except json.JSONDecodeError:
                continue
    return registos
