from collections import Counter

def contar_falhas_por_ip(registos: list[dict]) -> dict[str, int]:
    """Conta quantas falhas cada IP teve."""
    cont = Counter()
    for r in registos:
        if not r["sucesso"]:
            cont[r["ip"]] += 1
    return dict(cont)

def top_utilizadores_visados(registos: list[dict], k: int = 3) -> list[tuple[str,int]]:
    """Mostra os utilizadores com mais falhas de login."""
    cont = Counter()
    for r in registos:
        if not r["sucesso"]:
            cont[r["utilizador"]] += 1
    return cont.most_common(k)

def percentagem_sucesso(registos: list[dict]) -> dict[str, float]:
    """Calcula a percentagem de sucesso e falha global."""
    total = len(registos)
    if total == 0:
        return {"sucesso": 0.0, "falha": 0.0}
    sucesso = sum(1 for r in registos if r["sucesso"])
    falha = total - sucesso
    return {
        "sucesso": round(sucesso / total * 100, 2),
        "falha": round(falha / total * 100, 2)
    }

def ips_suspeitos(contagens: dict[str, int], limite: int = 3) -> list[str]:
    """Identifica IPs com número de falhas igual ou superior ao limite."""
    return [ip for ip, n in contagens.items() if n >= limite]
