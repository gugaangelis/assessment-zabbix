#!/usr/bin/env python3
"""
zabbix_assessment.py - Assessment SOMENTE LEITURA de um ambiente Zabbix (5.0 a 7.x) alinhado a boas práticas de
observabilidade/SRE, em 5 pilares:
  Confiabilidade da plataforma · Cobertura de monitoramento · Qualidade de alertas · Resposta e operação · Segurança e governança

Levanta o que existe (server/HA, proxies, filas, caches, hosts, templates, itens, LLD, triggers, problemas, eventos,
notificações, usuários, tokens, segredos), aponta lacunas por pilar com recomendação e gera relatório para stakeholders.

Gera: relatorio.html (stakeholders) · dados.json (bruto; checks/scores/scores_pilar/score_global)
      achados.csv (backlog por pilar) · cobertura_hosts.csv (host x disponibilidade/template/itens/triggers/tags/TLS/agente)
      cobertura_grupos.csv (host group x cobertura) · top_triggers.csv (mais disparos na janela, MTTR/MTTA)
      higiene_otimizacao.csv (itens não suportados, intervalos agressivos, hosts/templates órfãos; NVPS DE/PARA)
      relatorio_executivo.pdf (liderança) · relatorio_tecnico.pdf (engenharia, A4 paisagem)
      apresentacao_stakeholders.pptx (16:9, gráficos nativos editáveis e notas do apresentador)

Requisitos : Python 3.8+. A COLETA usa só a biblioteca padrão (roda em jump server sem internet/pip).
             PDF/PPTX (opcionais): `pip install --user reportlab python-pptx`; sem eles, essas saídas são puladas.
             Alternativa: coletar no jump server com --formats none e gerar PDF/PPTX na sua máquina com --render-only.
Autenticação:
  API token (recomendado, Zabbix 5.4+) : --token ou variável ZBX_TOKEN
  Usuário/senha                        : --user/ZBX_USER e senha em ZBX_PASSWORD ou prompt (sessão encerrada ao final)
  6.4+ envia "Authorization: Bearer"; versões anteriores usam o campo "auth" do JSON-RPC.
Permissão mínima (read-only garantido também no lado do Zabbix, 5.2+):
  Role "Assessment-ReadOnly" · User type: Super admin · UI elements: todos desmarcados · Actions: todas desmarcadas
  API access: Enabled · API methods: Allow list  ->  *.get   (+ user.login e user.logout se usar usuário/senha)
  Usuário em um grupo com Frontend access = Disabled (acesso só via API).
  Com role Admin/User o assessment roda, mas coletores restritos (usuários, tokens, housekeeping, autenticação, HA)
  aparecem como "parcial" no apêndice e os controles dependentes ficam N/A.

Garantia de read-only: toda chamada passa por um filtro que só permite métodos *.get (+ apiinfo.version e
user.login/user.logout). Qualquer outro método levanta erro antes de sair da máquina.

Uso:
  export ZBX_URL='https://zabbix.interno/'   ;   read -rs ZBX_TOKEN && export ZBX_TOKEN
  python3 zabbix_assessment.py --test                                     (valida conexão e permissões e sai)
  python3 zabbix_assessment.py --customer "Assaí Atacadista" --env-name "Produção" --days 30
  python3 zabbix_assessment.py --insecure --no-proxy --formats none       (certificado interno, sem proxy, sem PDF/PPTX)
  python3 zabbix_assessment.py --groups "Linux*,Windows servers" --threads 4
  python3 zabbix_assessment.py --render-only ./zabbix-assessment-20261124-1600/dados.json
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import getpass
import html
import json
import os
import re
import ssl
import statistics
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, replace
from datetime import date, datetime
from itertools import count
from pathlib import Path
from typing import Any, Callable

# --------------------------------------------------------------------------- #
# Catálogos
# --------------------------------------------------------------------------- #

ZSEV = {0: "Não classificada", 1: "Informação", 2: "Atenção", 3: "Média", 4: "Alta", 5: "Desastre"}
ZSEV_HEX = {0: "#97AAB3", 1: "#7499FF", 2: "#FFC859", 3: "#FFA059", 4: "#E97659", 5: "#E45959"}
ITEM_TYPES = {0: "Zabbix agent", 2: "Trapper", 3: "Simple check", 5: "Internal", 7: "Zabbix agent (ativo)", 8: "Aggregate", 9: "Web item",
              10: "External check", 11: "Database monitor", 12: "IPMI", 13: "SSH", 14: "Telnet", 15: "Calculated", 16: "JMX",
              17: "SNMP trap", 18: "Dependente", 19: "HTTP agent", 20: "SNMP agent", 21: "Script", 22: "Browser"}
IFACE_TYPES = {1: "Agent", 2: "SNMP", 3: "IPMI", 4: "JMX"}
MEDIA_TYPES = {0: "E-mail", 1: "Script", 2: "SMS", 3: "Jabber", 4: "Webhook", 100: "Ez Texting"}
POLL_EXCLUDE = {2, 17, 18}  # trapper, SNMP trap e dependente não são coletados por intervalo
ONCALL_RE = re.compile(r"pagerduty|opsgenie|servicenow|jira|teams|slack|telegram|glpi|topdesk|zammad|otrs|znuny|signl4|squadcast|"
                       r"victorops|splunk|ilert|rocket|mattermost|discord|webex|google chat|express|line|zendesk|freshservice|itop|redmine|"
                       r"github|gitlab|mantis|event-driven|grafana|ansible|dynatrace|sysaid|manageengine|ivanti|cherwell|bmc|remedy|4me", re.I)
SECRET_MACRO_RE = re.compile(r"PASS|PWD|SECRET|TOKEN|APIKEY|API_KEY|PRIVATE|CREDENTIAL|COMMUNITY|AUTH", re.I)
PROC_RE = re.compile(r"^zabbix\[process,([^,\]]+),avg,busy\]$")
CACHE_RE = re.compile(r"^zabbix\[(\w+),(\w+),(pused|pfree)\]$")
DUR_RE = re.compile(r"^\s*(\d+)\s*([smhdw]?)\s*$")
UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}

# Ciclo de vida (zabbix.com/life_cycle_and_release_policy): versão -> (fim do suporte completo, fim do suporte limitado)
SUPPORT = {(5, 0): ("2023-05-31", "2025-05-31"), (6, 0): ("2025-02-28", "2027-02-28"), (7, 0): ("2027-06-30", "2029-06-30"),
           (7, 2): ("2025-06-30", "2025-12-31"), (7, 4): ("2026-09-30", "2026-12-31"), (8, 0): ("2028-12-31", "2030-12-31")}

P_PLAT, P_COV, P_ALR, P_OPS, P_SEC = ("Confiabilidade da plataforma", "Cobertura de monitoramento", "Qualidade de alertas",
                                      "Resposta e operação", "Segurança e governança")
PILLARS = (P_PLAT, P_COV, P_ALR, P_OPS, P_SEC)
D_VER, D_HA, D_CAP, D_HK = "Versões & ciclo de vida", "Alta disponibilidade", "Capacidade & desempenho", "Retenção & housekeeping"
D_HOST, D_TPL, D_DATA, D_SYN = "Hosts & disponibilidade", "Templates & padronização", "Coleta (itens & LLD)", "Sintético & serviços de negócio"
D_TRG, D_NOISE, D_PROB = "Triggers & severidade", "Ruído & flapping", "Problemas em aberto"
D_NOTIF, D_INT, D_MAINT, D_RESP = "Notificações & escalonamento", "Integrações (ITSM/on-call)", "Manutenção & supressão", "Tempo de resposta"
D_IAM, D_ENC, D_AUD = "Identidade & acesso", "Criptografia & segredos", "Auditoria"
DOMAIN_PILLAR = {D_VER: P_PLAT, D_HA: P_PLAT, D_CAP: P_PLAT, D_HK: P_PLAT, D_HOST: P_COV, D_TPL: P_COV, D_DATA: P_COV, D_SYN: P_COV,
                 D_TRG: P_ALR, D_NOISE: P_ALR, D_PROB: P_ALR, D_NOTIF: P_OPS, D_INT: P_OPS, D_MAINT: P_OPS, D_RESP: P_OPS,
                 D_IAM: P_SEC, D_ENC: P_SEC, D_AUD: P_SEC}
SEV_ORDER = {"Alta": 0, "Média": 1, "Baixa": 2}
SEV_W = {"Alta": 3, "Média": 2, "Baixa": 1}

_lock = threading.Lock()


def log(msg: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] {msg}", file=sys.stderr)


def pct(a: int | float, b: int | float) -> int:
    return round(100 * a / b) if b else 0


def clip(s: Any, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def num(v: Any, dec: int = 0) -> str:
    if v is None:
        return "N/D"
    return f"{v:,.{dec}f}".replace(",", "X").replace(".", ",").replace("X", ".")


def dur_s(v: Any) -> int | None:
    """'30s','5m','1h','90d','60' -> segundos; macro/intervalo flexível -> None."""
    if v is None:
        return None
    m = DUR_RE.match(str(v).split(";")[0])
    return int(m.group(1)) * UNITS[m.group(2)] if m else None


def norm_err(e: Any) -> str:
    return clip(re.sub(r"\d+", "#", re.sub(r"\s+", " ", str(e or "sem mensagem"))).strip(), 110)


def chunks(lst: list, n: int) -> list[list]:
    return [lst[i:i + n] for i in range(0, len(lst), n)]


def pmap(fn: Callable, items: list, threads: int) -> list:
    if not items:
        return []
    with ThreadPoolExecutor(max_workers=max(1, threads)) as ex:
        return list(ex.map(fn, items))


def i0(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def median(v: list) -> float | None:
    return round(statistics.median(v), 1) if v else None


def p90(v: list) -> float | None:
    s = sorted(v)
    return round(s[max(0, int(len(s) * 0.9) - 1)], 1) if len(s) >= 10 else None


# --------------------------------------------------------------------------- #
# Cliente JSON-RPC (read-only, somente biblioteca padrão)
# --------------------------------------------------------------------------- #

READ_RE = re.compile(r"^[a-z]+\.get$")
AUTH_METHODS = {"apiinfo.version", "user.login", "user.logout"}


class ZbxError(Exception):
    def __init__(self, method: str, code: Any, message: str, data: str = ""):
        super().__init__(f"{method}: {code} {message} {data}".strip())
        self.code, self.message, self.data = code, message, data


class Zabbix:
    """Cliente mínimo da API. Só executa métodos *.get (+ versão/login/logout)."""

    def __init__(self, url: str, token: str | None = None, user: str | None = None, password: str | None = None,
                 insecure: bool = False, ca: str | None = None, timeout: int = 180, no_proxy: bool = False):
        u = url.strip().rstrip("/")
        self.url = u if u.endswith("api_jsonrpc.php") else u + "/api_jsonrpc.php"
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        if insecure:
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        handlers: list[Any] = [urllib.request.HTTPSHandler(context=ctx)]
        if no_proxy:
            handlers.append(urllib.request.ProxyHandler({}))
        self._op = urllib.request.build_opener(*handlers)
        self.timeout, self.stats, self._id, self._auth, self._session = timeout, Counter(), count(1), None, False
        self.version = str(self._post("apiinfo.version", {}, auth=False))
        n = [int(x) for x in re.findall(r"\d+", self.version)[:2]] + [0, 0]
        self.ver = (n[0], n[1])
        self._bearer = self.ver >= (6, 4)
        if token:
            self._auth, self.auth_mode = token, "api_token"
        elif user:
            key = "username" if self.ver >= (5, 4) else "user"
            self._auth = self._post("user.login", {key: user, "password": password or ""}, auth=False)
            self._session, self.auth_mode = True, "usuario_senha"
        else:
            raise ValueError("informe --token/ZBX_TOKEN ou --user/ZBX_USER")

    def _post(self, method: str, params: Any, auth: bool = True) -> Any:
        body = {"jsonrpc": "2.0", "method": method, "params": params, "id": next(self._id)}
        hdr = {"Content-Type": "application/json-rpc", "User-Agent": "zabbix-assessment/1.0"}
        if auth and self._auth:
            if self._bearer:
                hdr["Authorization"] = "Bearer " + self._auth
            else:
                body["auth"] = self._auth
        data = json.dumps(body).encode("utf-8")
        res: dict = {}
        for attempt in range(4):
            try:
                req = urllib.request.Request(self.url, data=data, headers=hdr, method="POST")
                with self._op.open(req, timeout=self.timeout) as r:
                    res = json.loads(r.read().decode("utf-8"))
                break
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504) and attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                raise
            except OSError:
                if attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                raise
        if "error" in res:
            er = res["error"]
            raise ZbxError(method, er.get("code"), er.get("message", ""), str(er.get("data", "")))
        return res.get("result")

    def call(self, method: str, **params: Any) -> Any:
        if not (READ_RE.match(method) or method in AUTH_METHODS):
            raise PermissionError(f"método '{method}' bloqueado: assessment somente leitura")
        with _lock:
            self.stats["calls"] += 1
        return self._post(method, params)

    def close(self) -> None:
        if self._session:
            try:
                self._post("user.logout", [])
            except Exception:  # noqa: BLE001
                pass


class Errors:
    """Contabiliza negações/erros por coletor sem derrubar o assessment."""

    def __init__(self):
        self.e: dict[str, Counter] = defaultdict(Counter)
        self.na: dict[str, str] = {}

    def run(self, key: str, fn: Callable, default: Any = None) -> Any:
        try:
            return fn()
        except PermissionError:
            raise
        except ZbxError as exc:
            with _lock:
                self.e[key][f"API {exc.code} {clip(exc.data or exc.message, 70)}"] += 1
        except Exception as exc:  # noqa: BLE001
            with _lock:
                self.e[key][f"erro {type(exc).__name__}: {clip(exc, 60)}"] += 1
        return default

    def since(self, Z: Zabbix, key: str, v: tuple, fn: Callable, default: Any = None) -> Any:
        """Executa só se a versão suporta o método; senão marca N/A."""
        if Z.ver >= v:
            return self.run(key, fn, default)
        self.na[key] = f"n/a (requer {v[0]}.{v[1]}+)"
        return None

    def status(self, key: str) -> str:
        if key in self.na and key not in self.e:
            return self.na[key]
        c = self.e.get(key)
        return "ok" if not c else "parcial: " + ", ".join(f"{k} x{v}" for k, v in c.most_common(2))


# --------------------------------------------------------------------------- #
# Coletores
# --------------------------------------------------------------------------- #


def support_status(ver: tuple, today: date | None = None) -> dict:
    today = today or date.today()
    known = sorted(SUPPORT)
    lts = ver[1] == 0
    if ver in SUPPORT:
        full, lim = (date.fromisoformat(x) for x in SUPPORT[ver])
        st = "completo" if today <= full else "limitado" if today <= lim else "EOL"
        return {"status": st, "fim_completo": full.isoformat(), "fim_limitado": lim.isoformat(), "lts": lts}
    if ver > known[-1]:
        return {"status": "completo", "fim_completo": None, "fim_limitado": None, "lts": lts}
    return {"status": "EOL", "fim_completo": None, "fim_limitado": None, "lts": lts}


def collect_platform(Z: Zabbix, E: Errors) -> dict:
    o: dict[str, Any] = {"versao": Z.version, "ver": list(Z.ver), "suporte": support_status(Z.ver)}
    nodes = E.since(Z, "ha", (6, 0), lambda: Z.call("hanode.get", output="extend"), [])
    o["ha_nodes"] = None if nodes is None else [
        {"name": n.get("name") or "(standalone)", "address": n.get("address", ""), "status": i0(n.get("status")),
         "lastaccess": i0(n.get("lastaccess"))} for n in nodes]
    o["settings"] = E.since(Z, "settings", (5, 2), lambda: Z.call("settings.get", output="extend"), {}) or {}
    o["housekeeping"] = E.since(Z, "housekeeping", (5, 2), lambda: Z.call("housekeeping.get", output="extend"), {}) or {}
    o["authentication"] = E.since(Z, "authentication", (5, 2), lambda: Z.call("authentication.get", output="extend"), {}) or {}
    return o


def collect_proxies(Z: Zabbix, E: Errors) -> tuple[list[dict], list[dict] | None]:
    v7, now = Z.ver >= (7, 0), time.time()
    out = (["proxyid", "name", "operating_mode", "lastaccess", "version", "compatibility", "state", "tls_connect", "tls_accept", "proxy_groupid"]
           if v7 else ["proxyid", "host", "status", "lastaccess", "tls_connect", "tls_accept"])
    raw = E.run("proxies", lambda: Z.call("proxy.get", output=out), []) or []
    res = []
    for p in raw:
        la = i0(p.get("lastaccess"))
        if v7:
            active, st = str(p.get("operating_mode")) == "0", i0(p.get("state"))
            online = True if st == 2 else False if st == 1 else (now - la < 600 if la else None)
        else:
            active = str(p.get("status")) == "5"
            online = (now - la < 600) if la else False
        res.append({"id": p.get("proxyid"), "name": p.get("name") or p.get("host"), "modo": "ativo" if active else "passivo",
                    "online": online, "lastaccess_min": round((now - la) / 60) if la else None, "versao": p.get("version"),
                    "compat": i0(p.get("compatibility")) if v7 else None, "grupo": p.get("proxy_groupid") if v7 else None,
                    "tls": str(p.get("tls_connect")) != "1" and (i0(p.get("tls_accept")) & 1) == 0})
    groups = E.since(Z, "proxy_groups", (7, 0), lambda: Z.call("proxygroup.get", output=["proxy_groupid", "name", "min_online", "state"]), [])
    return res, groups


def collect_hosts(Z: Zabbix, E: Errors, threads: int, only_groups: list[str]) -> list[dict]:
    v7, v54 = Z.ver >= (7, 0), Z.ver >= (5, 4)
    gkey = "selectHostGroups" if Z.ver >= (6, 2) else "selectGroups"
    flt: dict[str, Any] = {}
    if only_groups:
        allg = E.run("hosts", lambda: Z.call("hostgroup.get", output=["groupid", "name"]), []) or []
        pats = [p.strip().lower() for p in only_groups if p.strip()]
        gids = [g["groupid"] for g in allg if any(fnmatch.fnmatch(g["name"].lower(), p) for p in pats)]
        if not gids:
            raise SystemExit(f"--groups não encontrou host groups para: {', '.join(only_groups)}")
        flt["groupids"] = gids
    ids = [h["hostid"] for h in (E.run("hosts", lambda: Z.call("host.get", output=["hostid"], **flt), []) or [])]
    out = ["hostid", "host", "name", "status", "maintenance_status", "flags", "tls_connect", "tls_accept", "inventory_mode"]
    out += ["proxyid", "active_available"] if v7 else ["proxy_hostid"]
    if not v54:
        out += ["available", "snmp_available", "ipmi_available", "jmx_available", "error"]
    iface = ["type", "main", "error"] + (["available"] if v54 else [])
    kw = {"output": out, "selectInterfaces": iface, "selectParentTemplates": ["templateid", "name"], "selectTags": ["tag", "value"],
          "selectItems": "count", "selectTriggers": "count", gkey: ["groupid", "name"]}

    def run(hids):
        return E.run("hosts", lambda: Z.call("host.get", hostids=hids, **kw), []) or []

    raw = [h for part in pmap(run, chunks(ids, 300), threads) for h in part]
    hosts = []
    for h in raw:
        ifs = h.get("interfaces") or []
        if v54:
            av = [i0(i.get("available")) for i in ifs if str(i.get("main")) == "1"]
            err = next((i.get("error") for i in ifs if i.get("error")), "")
        else:
            av = [i0(h.get(k)) for k in ("available", "snmp_available", "ipmi_available", "jmx_available")]
            err = h.get("error", "")
        avail = 2 if 2 in av else 1 if 1 in av else 0
        types = sorted({i0(i.get("type")) for i in ifs})
        hosts.append({
            "id": h["hostid"], "host": h.get("host"), "name": h.get("name") or h.get("host"),
            "monitored": str(h.get("status")) == "0", "maint": str(h.get("maintenance_status")) == "1", "discovered": str(h.get("flags")) == "4",
            "groups": sorted(g["name"] for g in (h.get("hostgroups") or h.get("groups") or [])),
            "templates": sorted(t["name"] for t in h.get("parentTemplates") or []), "templateids": [t["templateid"] for t in h.get("parentTemplates") or []],
            "itens": i0(h.get("items")), "triggers": i0(h.get("triggers")), "avail": avail, "erro_iface": clip(err or "", 140),
            "active_avail": i0(h.get("active_available")) if v7 else None, "ifaces": types,
            "agent_iface": 1 in types, "proxy": h.get("proxyid") or h.get("proxy_hostid") or "0",
            "tls": str(h.get("tls_connect")) != "1" and (i0(h.get("tls_accept")) & 1) == 0,
            "tags": bool(h.get("tags")), "inventory": str(h.get("inventory_mode", "-1")) != "-1"})
    return hosts


def collect_templates(Z: Zabbix, E: Errors) -> list[dict]:
    v64 = Z.ver >= (6, 4)
    out = ["templateid", "host", "name"] + (["vendor_name", "vendor_version"] if v64 else [])
    raw = E.run("templates", lambda: Z.call("template.get", output=out, selectHosts="count", selectParentTemplates=["templateid"]), []) or []
    used_by_tpl = Counter(p["templateid"] for t in raw for p in t.get("parentTemplates") or [])
    res = []
    for t in raw:
        res.append({"id": t["templateid"], "name": t.get("name") or t.get("host"), "hosts": i0(t.get("hosts")),
                    "em_templates": used_by_tpl.get(t["templateid"], 0), "vendor": t.get("vendor_name") or "", "vendor_version": t.get("vendor_version") or ""})
    return res


def _new_items() -> dict:
    return {"total": 0, "habilitados": 0, "nao_suportados": 0, "agressivos": 0, "hist_longo": 0, "descobertos": 0, "intervalo_macro": 0,
            "nvps": 0.0, "por_tipo": Counter(), "erros": Counter(), "por_host": {}}


def collect_items(Z: Zabbix, E: Errors, hosts: list[dict], threads: int) -> dict:
    mon = {h["id"] for h in hosts if h["monitored"]}
    out = ["itemid", "hostid", "type", "delay", "history", "status", "state", "error", "flags"]

    def run(hids):
        rows = E.run("items", lambda: Z.call("item.get", hostids=hids, webitems=True, output=out), []) or []
        a = _new_items()
        for it in rows:
            a["total"] += 1
            if it.get("hostid") not in mon or str(it.get("status")) != "0":
                continue
            t = i0(it.get("type"))
            ph = a["por_host"].setdefault(it["hostid"], [0, 0, 0.0, 0.0, 0, 0.0, 0])  # hab, uns, nvps, nvps_uns, agr, nvps_agr, hist
            a["habilitados"] += 1
            ph[0] += 1
            a["por_tipo"][t] += 1
            a["descobertos"] += str(it.get("flags")) == "4"
            dl = None
            if t not in POLL_EXCLUDE:
                dl = dur_s(it.get("delay"))
                a["intervalo_macro"] += dl is None and "{$" in str(it.get("delay"))
            nv = 1.0 / dl if dl else 0.0
            a["nvps"] += nv
            ph[2] += nv
            if str(it.get("state")) == "1":
                a["nao_suportados"] += 1
                ph[1] += 1
                ph[3] += nv
                a["erros"][norm_err(it.get("error"))] += 1
            if dl and dl < 60:
                a["agressivos"] += 1
                ph[4] += 1
                ph[5] += nv
            hs = dur_s(it.get("history"))
            if hs and hs > 90 * 86400:
                a["hist_longo"] += 1
                ph[6] += 1
        return a

    tot = _new_items()
    for a in pmap(run, chunks([h["id"] for h in hosts], 150), threads):
        for k in ("total", "habilitados", "nao_suportados", "agressivos", "hist_longo", "descobertos", "intervalo_macro", "nvps"):
            tot[k] += a[k]
        tot["por_tipo"].update(a["por_tipo"])
        tot["erros"].update(a["erros"])
        tot["por_host"].update(a["por_host"])
    return tot


def collect_lld(Z: Zabbix, E: Errors, hosts: list[dict], threads: int) -> dict:
    mon = {h["id"] for h in hosts if h["monitored"]}

    def run(hids):
        return E.run("lld", lambda: Z.call("discoveryrule.get", hostids=hids, output=["itemid", "hostid", "status", "state", "error"]), []) or []

    rows = [r for part in pmap(run, chunks([h["id"] for h in hosts], 300), threads) for r in part]
    en = [r for r in rows if r.get("hostid") in mon and str(r.get("status")) == "0"]
    bad = [r for r in en if str(r.get("state")) == "1"]
    return {"total": len(rows), "habilitadas": len(en), "nao_suportadas": len(bad), "erros": Counter(norm_err(r.get("error")) for r in bad).most_common(10)}


def collect_triggers(Z: Zabbix, E: Errors, hosts: list[dict], threads: int) -> dict:
    out = ["triggerid", "description", "priority", "status", "state", "value", "lastchange", "error"]

    def run(hids):
        rows = E.run("triggers", lambda: Z.call("trigger.get", hostids=hids, output=out, selectDependencies=["triggerid"], selectTags=["tag"],
                                                selectHosts=["hostid"], expandDescription=True), []) or []
        return [(r["triggerid"], i0(r.get("priority")), str(r.get("status")), str(r.get("state")), str(r.get("value")), i0(r.get("lastchange")),
                 bool(r.get("dependencies")), bool(r.get("tags")), [x["hostid"] for x in r.get("hosts") or []], r.get("description", ""),
                 clip(r.get("error") or "", 120)) for r in rows]

    seen: dict[str, tuple] = {}
    for part in pmap(run, chunks([h["id"] for h in hosts], 150), threads):
        for t in part:
            seen[t[0]] = t
    return seen


def collect_problems(Z: Zabbix, E: Errors) -> list[dict]:
    return E.run("problems", lambda: Z.call("problem.get", output=["eventid", "objectid", "clock", "severity", "acknowledged", "suppressed", "name"],
                                            source=0, object=0, recent=False, sortfield=["eventid"], sortorder="DESC"), []) or []


def collect_events(Z: Zabbix, E: Errors, days: int, threads: int, cap: int) -> tuple[list[dict], bool]:
    now = int(time.time())
    wins = [(s, min(s + 86400, now)) for s in range(now - days * 86400, now, 86400)]

    def run(w):
        return E.run("events", lambda: Z.call("event.get", source=0, object=0, value=1, time_from=w[0], time_till=w[1] - 1,
                                              output=["eventid", "clock", "r_eventid", "objectid", "severity", "name"],
                                              select_acknowledges=["clock", "action"], sortfield=["clock"], sortorder="ASC", limit=cap), []) or []

    parts = pmap(run, wins, threads)
    evs = [e for p in parts for e in p]
    truncated = any(len(p) >= cap for p in parts)
    rids = sorted({e["r_eventid"] for e in evs if str(e.get("r_eventid") or "0") != "0"})

    def rec(ch):
        return E.run("events", lambda: Z.call("event.get", source=0, object=0, eventids=ch, output=["eventid", "clock"]), []) or []

    rclock = {r["eventid"]: i0(r["clock"]) for p in pmap(rec, chunks(rids, 2000), threads) for r in p}
    out = []
    for e in evs:
        c = i0(e.get("clock"))
        rc = rclock.get(e.get("r_eventid"))
        acks = [i0(a.get("clock")) for a in e.get("acknowledges") or [] if i0(a.get("action")) & 2]
        out.append({"t": e.get("objectid"), "c": c, "s": i0(e.get("severity")), "n": e.get("name", ""),
                    "dur": (rc - c) if rc and rc >= c else None, "ack": (min(acks) - c) if acks else None})
    return out, truncated


def collect_alerts(Z: Zabbix, E: Errors, days: int) -> dict:
    tf = int(time.time()) - days * 86400
    total = i0(E.run("alerts", lambda: Z.call("alert.get", time_from=tf, filter={"alerttype": 0}, countOutput=True), 0))
    failed = i0(E.run("alerts", lambda: Z.call("alert.get", time_from=tf, filter={"alerttype": 0, "status": 2}, countOutput=True), 0))
    rows = E.run("alerts", lambda: Z.call("alert.get", time_from=tf, filter={"alerttype": 0, "status": 2}, output=["mediatypeid", "error"],
                                          sortfield="alertid", sortorder="DESC", limit=5000), []) or []
    return {"total": total, "falhas": failed, "erros": Counter(norm_err(r.get("error")) for r in rows).most_common(10),
            "falhas_por_media": dict(Counter(r.get("mediatypeid") for r in rows))}


def collect_config(Z: Zabbix, E: Errors) -> dict:
    o: dict[str, Any] = {}
    ukey = "username" if Z.ver >= (5, 4) else "alias"
    o["actions"] = E.run("actions", lambda: Z.call(
        "action.get", output=["actionid", "name", "eventsource", "status", "esc_period", "pause_suppressed"],
        selectOperations=["operationtype", "esc_step_from", "esc_step_to"], selectRecoveryOperations=["operationtype"],
        selectUpdateOperations=["operationtype"], selectFilter=["conditions"]), []) or []
    o["mediatypes"] = E.run("mediatypes", lambda: Z.call("mediatype.get", output=["mediatypeid", "name", "type", "status"]), []) or []
    uout = ["userid", ukey, "name", "surname", "autologout"] + (["roleid"] if Z.ver >= (5, 2) else ["type"]) + (["userdirectoryid"] if Z.ver >= (6, 4) else [])
    users = E.run("users", lambda: Z.call("user.get", output=uout, selectMedias=["mediatypeid", "active", "severity"],
                                          selectUsrgrps=["usrgrpid", "name", "gui_access", "users_status", "debug_mode"]), []) or []
    for u in users:
        u["username"] = u.get(ukey) or u.get("username") or u.get("alias")
    o["users"] = users
    o["roles"] = E.since(Z, "roles", (5, 2), lambda: Z.call("role.get", output=["roleid", "name", "type", "readonly"]), [])
    gout = ["usrgrpid", "name", "gui_access", "users_status", "debug_mode"] + (["mfa_status"] if Z.ver >= (7, 0) else [])
    o["usergroups"] = E.run("usergroups", lambda: Z.call("usergroup.get", output=gout, selectUsers=["userid"]), []) or []
    o["tokens"] = E.since(Z, "tokens", (5, 4), lambda: Z.call("token.get", output=["tokenid", "name", "userid", "expires_at", "status", "lastaccess", "created_at"]), None)
    o["scripts"] = E.run("scripts", lambda: Z.call("script.get", output=["scriptid", "name", "type", "execute_on", "usrgrpid", "groupid"]), []) or []
    o["global_macros"] = E.run("macros", lambda: Z.call("usermacro.get", globalmacro=True, output=["macro", "type"]), []) or []
    o["host_macros"] = E.run("macros", lambda: Z.call("usermacro.get", output=["macro", "type", "hostid"]), []) or []
    o["maintenances"] = E.run("maintenance", lambda: Z.call("maintenance.get", output=["maintenanceid", "name", "active_since", "active_till", "maintenance_type"]), []) or []
    o["httptests"] = E.run("web", lambda: Z.call("httptest.get", output=["httptestid", "name", "status", "hostid"]), []) or []
    o["drules"] = E.run("discovery", lambda: Z.call("drule.get", output=["druleid", "name", "status"]), []) or []
    o["services"] = E.since(Z, "services", (6, 0), lambda: i0(Z.call("service.get", countOutput=True)), 0)
    o["slas"] = E.since(Z, "services", (6, 0), lambda: Z.call("sla.get", output=["slaid", "name", "status", "slo"]), [])
    o["dashboards"] = i0(E.run("dashboards", lambda: Z.call("dashboard.get", countOutput=True), 0))
    o["reports"] = E.since(Z, "reports", (5, 4), lambda: i0(Z.call("report.get", countOutput=True)), 0)
    o["connectors"] = E.since(Z, "connectors", (6, 4), lambda: Z.call("connector.get", output=["connectorid", "name", "status"]), [])
    return o


def collect_agents(Z: Zabbix, E: Errors) -> dict[str, dict]:
    rows = E.run("agents", lambda: Z.call("item.get", filter={"key_": ["agent.version", "agent.variant"]}, monitored=True,
                                          output=["hostid", "key_", "lastvalue", "lastclock"]), []) or []
    res: dict[str, dict] = defaultdict(dict)
    for r in rows:
        if i0(r.get("lastclock")):
            res[r["hostid"]]["versao" if r["key_"] == "agent.version" else "variante"] = str(r.get("lastvalue") or "")
    return dict(res)


def collect_internal(Z: Zabbix, E: Errors) -> list[dict]:
    return E.run("self_monitoring", lambda: Z.call("item.get", search={"key_": "zabbix["}, startSearch=True, monitored=True,
                                                   output=["hostid", "key_", "lastvalue", "lastclock"]), []) or []


# --------------------------------------------------------------------------- #
# Consolidação
# --------------------------------------------------------------------------- #


def parse_internal(rows: list[dict], names: dict[str, str]) -> dict:
    """Self-monitoring (itens zabbix[...]) por host: identifica server (vcache/alerter/escalator) e proxies."""
    now = time.time()
    kv_by: dict[str, dict] = defaultdict(dict)
    stale = 0
    for r in rows:
        try:
            v = float(r.get("lastvalue"))
        except (TypeError, ValueError):
            continue
        if now - i0(r.get("lastclock")) > 3600:
            stale += 1
            continue
        kv_by[r["hostid"]][r["key_"]] = v

    def rec(hid, kv):
        caches = {}
        for k, v in kv.items():
            m = CACHE_RE.match(k)
            if m:
                caches[f"{m.group(1)}.{m.group(2)}"] = round(v if m.group(3) == "pused" else 100 - v, 1)
        nv = kv.get("zabbix[wcache,values]")
        return {"host": names.get(hid, hid), "processos": {m.group(1): round(v, 1) for k, v in kv.items() if (m := PROC_RE.match(k))},
                "caches": caches, "queue_10m": kv.get("zabbix[queue,10m]"), "queue": kv.get("zabbix[queue]"),
                "nvps": round(nv, 1) if nv is not None and nv < 1e6 else None, "nvps_requerido": kv.get("zabbix[requiredperformance]"),
                "vcache_lowmem": kv.get("zabbix[vcache,cache,mode]"), "preproc_queue": kv.get("zabbix[preprocessing_queue]"),
                "lld_queue": kv.get("zabbix[lld_queue]"), "chaves": len(kv)}

    servers, proxies = [], []
    for hid, kv in kv_by.items():
        is_srv = any(k.startswith(("zabbix[vcache", "zabbix[process,alerter", "zabbix[process,escalator")) for k in kv)
        (servers if is_srv else proxies).append(rec(hid, kv))
    servers.sort(key=lambda r: -r["chaves"])
    return {"server": servers[0] if servers else None, "proxies": [p for p in proxies if p["processos"] or p["caches"]], "itens_desatualizados": stale}


def summarize_triggers(d: dict, trig: dict[str, tuple]) -> None:
    hosts = d["hosts"]
    mon = {h["id"] for h in hosts if h["monitored"]}
    now = time.time()
    en = [t for t in trig.values() if t[2] == "0" and any(h in mon for h in t[8])]
    per_host = Counter(h for t in en for h in t[8])
    for h in hosts:
        h["trig_hab"] = per_host.get(h["id"], 0)
    names = {h["id"]: h["name"] for h in hosts}
    old = sorted((t for t in en if t[4] == "1" and now - t[5] > 30 * 86400), key=lambda t: t[5])
    d["triggers"] = {
        "total": len(trig), "habilitadas": len(en), "por_severidade": {ZSEV[s]: sum(1 for t in en if t[1] == s) for s in ZSEV},
        "nao_classificadas": sum(1 for t in en if t[1] == 0), "desconhecidas": sum(1 for t in en if t[3] == "1"),
        "erros": Counter(norm_err(t[10]) for t in en if t[3] == "1").most_common(10),
        "com_dependencia": sum(1 for t in en if t[6]), "com_tags": sum(1 for t in en if t[7]), "em_problema": sum(1 for t in en if t[4] == "1"),
        "problema_30d": len(old),
        "problema_30d_lista": [{"id": t[0], "nome": t[9], "host": ", ".join(names.get(h, h) for h in t[8][:2]), "sev": ZSEV[t[1]],
                                "dias": round((now - t[5]) / 86400)} for t in old[:200]],
    }
    d["_trig_names"] = {t[0]: (t[9], ", ".join(names.get(h, h) for h in t[8][:2])) for t in trig.values()}


def summarize_problems(d: dict, probs: list[dict]) -> None:
    now = time.time()
    tn = d.get("_trig_names", {})
    rows = []
    for p in probs:
        c, s = i0(p.get("clock")), i0(p.get("severity"))
        rows.append({"t": p.get("objectid"), "s": s, "dias": (now - c) / 86400, "ack": str(p.get("acknowledged")) == "1",
                     "sup": str(p.get("suppressed")) == "1", "n": p.get("name", "")})
    hi = [r for r in rows if r["s"] >= 4]
    sev3 = [r for r in rows if r["s"] >= 3]
    d["problems"] = {
        "abertos": len(rows), "por_severidade": {ZSEV[s]: sum(1 for r in rows if r["s"] == s) for s in ZSEV},
        "high_disaster": len(hi), "high_disaster_sem_ack_24h": sum(1 for r in hi if not r["ack"] and r["dias"] > 1),
        "sev3_mais": len(sev3), "sev3_ack": sum(1 for r in sev3 if r["ack"]), "suprimidos": sum(1 for r in rows if r["sup"]),
        "mais_30d": sum(1 for r in rows if r["dias"] > 30), "mais_7d": sum(1 for r in rows if r["dias"] > 7),
        "mais_antigos": [{"nome": r["n"], "host": tn.get(r["t"], ("", ""))[1], "sev": ZSEV[r["s"]], "dias": round(r["dias"]), "ack": r["ack"]}
                         for r in sorted(rows, key=lambda r: -r["dias"])[:30]],
    }


def summarize_events(d: dict, evs: list[dict], truncated: bool) -> None:
    days = d["meta"]["days"]
    tn = d.get("_trig_names", {})
    by_t: dict[str, list] = defaultdict(list)
    for e in evs:
        by_t[e["t"]].append(e)
    durs = [e["dur"] / 60 for e in evs if e["dur"] is not None]
    durs_hi = [e["dur"] / 60 for e in evs if e["dur"] is not None and e["s"] >= 4]
    acks = [e["ack"] / 60 for e in evs if e["ack"] is not None]
    top, flap = [], []
    for t, lst in by_t.items():
        dd = [e["dur"] / 60 for e in lst if e["dur"] is not None]
        nm, hs = tn.get(t, (lst[-1]["n"], ""))
        row = {"trigger": nm or lst[-1]["n"], "host": hs, "sev": ZSEV[max(e["s"] for e in lst)], "disparos": len(lst),
               "mttr_mediana_min": median(dd), "mtta_mediana_min": median([e["ack"] / 60 for e in lst if e["ack"] is not None])}
        top.append(row)
        if len(lst) >= 10 and dd and statistics.median(dd) < 10:
            flap.append(row)
    top.sort(key=lambda r: -r["disparos"])
    flap.sort(key=lambda r: -r["disparos"])
    per_day = Counter(datetime.fromtimestamp(e["c"]).strftime("%Y-%m-%d") for e in evs)
    d["events"] = {
        "total": len(evs), "por_dia": round(len(evs) / days, 1) if days else 0, "truncado": truncated,
        "por_severidade": {ZSEV[s]: sum(1 for e in evs if e["s"] == s) for s in ZSEV}, "triggers_distintas": len(by_t),
        "resolvidos": len(durs), "curta_duracao": sum(1 for x in durs if x < 5), "mttr_mediana_min": median(durs), "mttr_p90_min": p90(durs),
        "mttr_hi_mediana_min": median(durs_hi), "reconhecidos": len(acks), "mtta_mediana_min": median(acks), "mtta_p90_min": p90(acks),
        "top_triggers": top[:50], "flapping": flap[:50], "flapping_total": len(flap), "serie_diaria": dict(sorted(per_day.items())),
    }


def summarize_config(d: dict, cfg: dict, alerts: dict) -> None:
    now = time.time()
    hosts_mon = {h["id"] for h in d["hosts"] if h["monitored"]}
    A = cfg["actions"]
    trg = [a for a in A if str(a.get("eventsource")) == "0"]
    en = [a for a in trg if str(a.get("status")) == "0"]
    msg_ops = lambda a: [o for o in a.get("operations") or [] if str(o.get("operationtype")) == "0"]  # noqa: E731
    mts = cfg["mediatypes"]
    mt_name = {m["mediatypeid"]: m.get("name") or m.get("description") or m["mediatypeid"] for m in mts}
    mt_en = [m for m in mts if str(m.get("status")) == "0"]
    users = cfg["users"]
    used_mt = Counter(md["mediatypeid"] for u in users for md in u.get("medias") or [] if str(md.get("active")) == "0")
    hooks = [m for m in mt_en if i0(m.get("type")) == 4]
    d["alerting"] = {
        "acoes_trigger": len(trg), "acoes_trigger_hab": len(en), "acoes_com_mensagem": sum(1 for a in en if msg_ops(a)),
        "acoes_com_escalonamento": sum(1 for a in en if any(i0(o.get("esc_step_from")) > 1 for o in a.get("operations") or [])),
        "acoes_com_recuperacao": sum(1 for a in en if a.get("recovery_operations") or a.get("recoveryOperations")),
        "acoes_com_update": sum(1 for a in en if a.get("update_operations") or a.get("updateOperations")),
        "acoes_pausam_suprimidos": sum(1 for a in en if str(a.get("pause_suppressed", "1")) == "1"),
        "acoes_internas_hab": sum(1 for a in A if str(a.get("eventsource")) == "3" and str(a.get("status")) == "0"),
        "acoes_autoregistro_hab": sum(1 for a in A if str(a.get("eventsource")) == "2" and str(a.get("status")) == "0"),
        "acoes_discovery_hab": sum(1 for a in A if str(a.get("eventsource")) == "1" and str(a.get("status")) == "0"),
        "media_types": len(mts), "media_types_hab": len(mt_en),
        "media_por_tipo": dict(Counter(MEDIA_TYPES.get(i0(m.get("type")), str(m.get("type"))) for m in mt_en)),
        "webhooks_hab": [m.get("name") for m in hooks], "integracoes_oncall": sorted({m.get("name") for m in mt_en if ONCALL_RE.search(m.get("name") or "")}),
        "media_em_uso": {mt_name.get(k, k): v for k, v in used_mt.most_common()}, "usuarios_com_media": sum(1 for u in users if any(str(m.get("active")) == "0" for m in u.get("medias") or [])),
        "alertas": {**alerts, "falhas_por_media": {mt_name.get(k, k): v for k, v in (alerts.get("falhas_por_media") or {}).items()}},
        "connectors": [c.get("name") for c in (cfg.get("connectors") or []) if str(c.get("status")) == "1"] if cfg.get("connectors") is not None else None,
    }
    M = cfg["maintenances"]
    d["maintenance"] = {"total": len(M), "expiradas": [m.get("name") for m in M if 0 < i0(m.get("active_till")) < now],
                        "vigentes": sum(1 for m in M if i0(m.get("active_since")) <= now <= i0(m.get("active_till")))}
    web = [w for w in cfg["httptests"] if w.get("hostid") in hosts_mon]
    d["synthetic"] = {"web_scenarios": len(cfg["httptests"]), "web_hab": sum(1 for w in web if str(w.get("status")) == "0"),
                      "discovery_rules": len(cfg["drules"]), "discovery_hab": sum(1 for r in cfg["drules"] if str(r.get("status")) == "0"),
                      "servicos": cfg.get("services"), "slas": None if cfg.get("slas") is None else len(cfg["slas"]),
                      "dashboards": cfg.get("dashboards"), "relatorios_agendados": cfg.get("reports")}
    # Segurança
    roles = {r["roleid"]: r for r in cfg.get("roles") or []}
    groups = {g["usrgrpid"]: g for g in cfg["usergroups"]}

    def user_type(u):
        if u.get("roleid"):
            return i0((roles.get(u["roleid"]) or {}).get("type")) or None
        return i0(u.get("type")) or None

    def active(u):
        gs = [groups.get(g["usrgrpid"], g) for g in u.get("usrgrps") or []]
        return not any(str(g.get("users_status")) == "1" for g in gs)

    def frontend(u):
        gs = [groups.get(g["usrgrpid"], g) for g in u.get("usrgrps") or []]
        return active(u) and not any(str(g.get("gui_access")) == "3" for g in gs)

    act = [u for u in users if active(u)]
    by_name = {str(u.get("username")).lower(): u for u in users}
    adm, guest = by_name.get("admin"), by_name.get("guest")
    tok = cfg.get("tokens")
    toks_on = [t for t in tok or [] if str(t.get("status")) == "0" and (i0(t.get("expires_at")) == 0 or i0(t.get("expires_at")) > now)]
    scripts_risk = [s.get("name") for s in cfg["scripts"] if str(s.get("type")) == "0" and str(s.get("execute_on")) in ("1", "2")
                    and str(s.get("usrgrpid") or "0") == "0"]
    sens = lambda ms: [m.get("macro") for m in ms if SECRET_MACRO_RE.search(m.get("macro") or "") and str(m.get("type", "0")) == "0"]  # noqa: E731
    au, st, hk = d["platform"]["authentication"], d["platform"]["settings"], d["platform"]["housekeeping"]
    audit = st.get("auditlog_enabled", hk.get("auditlog_enabled", au.get("auditlog_enabled")))
    d["security"] = {
        "usuarios": len(users), "usuarios_ativos": len(act), "usuarios_frontend": sum(1 for u in users if frontend(u)),
        "super_admins": sum(1 for u in act if user_type(u) == 3), "tipos_desconhecidos": not roles and any(u.get("roleid") for u in users),
        "admin_padrao_ativo": bool(adm and active(adm)) if users else None, "guest_ativo": bool(guest and frontend(guest)) if users else None,
        "grupos_debug": [g.get("name") for g in cfg["usergroups"] if str(g.get("debug_mode")) == "1"],
        "ldap": str(au.get("ldap_auth_enabled", au.get("ldap_configured", "0"))) == "1" or str(au.get("authentication_type")) == "1" if au else None,
        "saml": str(au.get("saml_auth_enabled", "0")) == "1" if au else None,
        "mfa": (str(au.get("mfa_status", "0")) == "1") if au and d["platform"]["ver"] >= [7, 0] else None,
        "grupos_mfa": sum(1 for g in cfg["usergroups"] if str(g.get("mfa_status", "0")) == "1"),
        "senha_min": i0(au.get("passwd_min_length")) if au.get("passwd_min_length") is not None else None,
        "senha_regras": bin(i0(au.get("passwd_check_rules"))).count("1") if au.get("passwd_check_rules") is not None else None,
        "tokens_total": None if tok is None else len(tok), "tokens_ativos": None if tok is None else len(toks_on),
        "tokens_sem_expiracao": None if tok is None else sum(1 for t in toks_on if i0(t.get("expires_at")) == 0),
        "tokens_sem_uso_90d": None if tok is None else sum(1 for t in toks_on if now - i0(t.get("lastaccess")) > 90 * 86400),
        "scripts_risco": scripts_risk, "scripts_total": len(cfg["scripts"]),
        "macros_globais_expostas": sens(cfg["global_macros"]), "macros_host_expostas": len(sens(cfg["host_macros"])),
        "macros_secret": sum(1 for m in cfg["global_macros"] + cfg["host_macros"] if str(m.get("type", "0")) in ("1", "2")),
        "audit_log": None if audit is None else str(audit) == "1",
        "audit_retencao_d": (dur_s(hk.get("hk_audit")) or 0) // 86400 if hk.get("hk_audit") else None,
    }


def compute_coverage(d: dict, agents: dict[str, dict]) -> None:
    pmap_ = {p["id"]: p["name"] for p in d["platform"]["proxies"]}
    for h in d["hosts"]:
        ag = agents.get(h["id"]) or {}
        h["agente_versao"], h["agente2"] = ag.get("versao", ""), ag.get("variante") == "2"
        h["proxy_nome"] = pmap_.get(h["proxy"], "server") if h["proxy"] not in ("0", None) else "server"
    agg: dict[str, dict] = {}
    for h in d["hosts"]:
        for g in h["groups"] or ["(sem grupo)"]:
            a = agg.setdefault(g, Counter())
            a["total"] += 1
            if not h["monitored"]:
                continue
            a["monitorados"] += 1
            a["disponiveis"] += h["avail"] != 2
            a["com_template"] += bool(h["templates"])
            a["com_trigger"] += h.get("trig_hab", h["triggers"]) > 0
            a["sem_nao_suportado"] += h.get("itens_uns", 0) == 0
            a["com_tag"] += h["tags"]
            a["com_tls"] += h["tls"]
    d["coverage"] = {g: dict(v) for g, v in sorted(agg.items(), key=lambda kv: -kv[1]["total"])}
    vers = Counter(".".join(h["agente_versao"].split(".")[:2]) for h in d["hosts"] if h["monitored"] and h["agente_versao"])
    d["agents"] = {"com_versao": sum(vers.values()), "versoes": dict(vers.most_common(15)),
                   "agent2": sum(1 for h in d["hosts"] if h["monitored"] and h["agente2"]),
                   "antigos": sum(n for v, n in vers.items() if tuple(i0(x) for x in v.split(".")) < (5, 0))}


# Premissa de NVPS (valores/s de polling) por categoria de higiene: (fração removida da carga, ação).
NVPS_RULES: dict[str, tuple[float | None, str]] = {
    "Itens não suportados": (1.00, "Corrigir ou desabilitar os itens (consomem pollers e geram ruído)"),
    "Host indisponível": (1.00, "Restabelecer a conectividade ou desabilitar o host (ocupa unreachable pollers)"),
    "Intervalo agressivo (< 60s)": (None, "Padronizar intervalo mínimo de 60s (exceto itens críticos justificados)"),
    "Histórico > 90 dias": (0.0, "Reduzir histórico para ≤ 31d e usar trends para longo prazo"),
    "Host sem template": (0.0, "Vincular template padrão (SO/serviço) ou remover o host"),
    "Host desabilitado": (0.0, "Confirmar descomissionamento e excluir"),
    "Template sem uso": (0.0, "Excluir ou arquivar templates customizados sem vínculo"),
    "Trigger em PROBLEM > 30 dias": (0.0, "Corrigir a causa, ajustar o limiar ou desabilitar"),
    "Manutenção expirada": (0.0, "Remover janelas de manutenção vencidas"),
    "Proxy offline": (0.0, "Restabelecer o proxy ou migrar os hosts"),
}


def build_hygiene(d: dict, ih: dict[str, list], templates: list[dict]) -> None:
    opp: list[dict] = []

    def add(cat, tipo, nome, grupo, det, de=None, para=None):
        opp.append({"categoria": cat, "tipo": tipo, "nome": nome, "grupo": grupo, "detalhe": det,
                    "nvps_de": None if de is None else round(de, 3), "nvps_para": None if para is None else round(para, 3)})

    for h in d["hosts"]:
        ph = ih.get(h["id"]) or [0, 0, 0.0, 0.0, 0, 0.0, 0]
        h.update({"itens_hab": ph[0], "itens_uns": ph[1], "nvps": round(ph[2], 3), "itens_agressivos": ph[4], "itens_hist_longo": ph[6]})
        g = ", ".join(h["groups"][:2])
        if not h["monitored"]:
            add("Host desabilitado", "Host", h["name"], g, "status desabilitado")
            continue
        if h["avail"] == 2:
            add("Host indisponível", "Host", h["name"], g, h["erro_iface"] or "interface principal indisponível", ph[2], 0.0)
        if not h["templates"] and not h["discovered"]:
            add("Host sem template", "Host", h["name"], g, f"{ph[0]} itens configurados direto no host")
        if ph[1] and h["avail"] != 2:
            add("Itens não suportados", "Host", h["name"], g, f"{ph[1]} de {ph[0]} itens não suportados", ph[3], 0.0)
        if ph[4]:
            add("Intervalo agressivo (< 60s)", "Host", h["name"], g, f"{ph[4]} itens com intervalo < 60s", ph[5], ph[4] / 60.0)
        if ph[6]:
            add("Histórico > 90 dias", "Host", h["name"], g, f"{ph[6]} itens com histórico > 90d")
    v64 = d["platform"]["ver"] >= [6, 4]
    for t in templates:
        custom = (not t["vendor"]) if v64 else not t["name"].startswith("Template ")
        if custom and not t["hosts"] and not t["em_templates"]:
            add("Template sem uso", "Template", t["name"], "—", "sem hosts e sem templates vinculados")
    for t in d["triggers"]["problema_30d_lista"]:
        add("Trigger em PROBLEM > 30 dias", "Trigger", t["nome"], t["host"], f"{t['sev']} · em problema há {t['dias']} dias")
    for m in d["maintenance"]["expiradas"]:
        add("Manutenção expirada", "Manutenção", m, "—", "janela vencida ainda cadastrada")
    for p in d["platform"]["proxies"]:
        if p["online"] is False:
            add("Proxy offline", "Proxy", p["name"], "—", f"modo {p['modo']} · último contato há {p['lastaccess_min'] or '?'} min")
    order = list(NVPS_RULES)
    opp.sort(key=lambda o: (order.index(o["categoria"]), -(o["nvps_de"] or 0)))
    base = d["items"]["nvps_estimado"] or 0
    rows: dict[str, dict] = {}
    for o in opp:
        if o["nvps_de"] is None:
            continue
        r = rows.setdefault(o["categoria"], {"categoria": o["categoria"], "acao": NVPS_RULES[o["categoria"]][1], "objetos": 0, "de": 0.0, "para": 0.0})
        r["objetos"] += 1
        r["de"] += o["nvps_de"]
        r["para"] += o["nvps_para"]
    dp = [{**r, "de": round(r["de"], 1), "para": round(r["para"], 1), "reducao": round(r["de"] - r["para"], 1),
           "pct_carga": round(100 * (r["de"] - r["para"]) / base, 1) if base else None} for r in rows.values()]
    d["hygiene"] = {"oportunidades": opp, "resumo": dict(Counter(o["categoria"] for o in opp)),
                    "de_para": sorted(dp, key=lambda r: -r["reducao"]) or None, "nvps_base": round(base, 1)}


# --------------------------------------------------------------------------- #
# Motor de avaliação
# --------------------------------------------------------------------------- #


@dataclass
class Check:
    domain: str
    severity: str
    title: str
    passed: bool | None
    evidence: str
    impact: str
    recommendation: str
    pillar: str = ""


def evaluate(d: dict) -> list[Check]:
    out: list[Check] = []
    PL, IT, TR, PR, EV = d["platform"], d["items"], d["triggers"], d["problems"], d["events"]
    AL, SE, SY, MT, AG, LL = d["alerting"], d["security"], d["synthetic"], d["maintenance"], d["agents"], d["lld"]
    I, ver, days = PL.get("interno") or {}, tuple(PL["ver"]), d["meta"]["days"]
    srv = I.get("server") or {}
    hosts = d["hosts"]
    mon = [h for h in hosts if h["monitored"]]
    nm = len(mon)

    def add(dom, sev, title, cond, ev, impact, reco, pillar=None):
        out.append(Check(dom, sev, title, cond, ev, impact, reco, pillar or DOMAIN_PILLAR[dom]))

    # ---------------- Confiabilidade da plataforma ---------------- #
    sp = PL["suporte"]
    lim = f"fim do suporte completo {sp['fim_completo']}, limitado {sp['fim_limitado']}" if sp.get("fim_limitado") else "datas não catalogadas"
    add(D_VER, "Alta", "Versão do Zabbix com suporte do fabricante", sp["status"] != "EOL",
        f"Zabbix {PL['versao']} · suporte {sp['status']} ({lim}).",
        "Versão sem suporte não recebe correções de segurança (CVE) nem de bugs críticos.",
        "Planejar upgrade para a LTS vigente (7.0 LTS) com ensaio em homologação e backup do banco.")
    if sp["status"] != "EOL":
        add(D_VER, "Baixa", "Versão em suporte completo", sp["status"] == "completo", f"Zabbix {PL['versao']} em suporte {sp['status']}.",
            "Suporte limitado cobre só falhas críticas e segurança.", "Agendar upgrade antes do fim do suporte limitado.")
    add(D_VER, "Baixa", "Versão LTS em produção", sp["lts"], f"{PL['versao']} {'é' if sp['lts'] else 'não é'} LTS (x.0).",
        "Versões standard têm ciclo curto (≈1 ano) e exigem upgrades frequentes.", "Padronizar produção em versões LTS (6.0/7.0).")
    pr = PL["proxies"]
    if pr and ver >= (7, 0):
        bad = [p["name"] for p in pr if p["compat"] in (2, 3)]
        add(D_VER, "Média", "Proxies na mesma versão do server", not bad, f"{len(bad)} de {len(pr)} proxies desatualizados/não suportados" + (f": {', '.join(bad[:5])}" if bad else "") + ".",
            "Proxy desatualizado perde funcionalidades e pode parar de coletar após upgrade do server.", "Atualizar proxies para a mesma versão major.minor do server.")
    if AG["com_versao"]:
        add(D_VER, "Média", "Agentes em versão suportada (≥ 5.0)", pct(AG["antigos"], AG["com_versao"]) <= 5,
            f"{AG['antigos']} de {AG['com_versao']} agentes com versão < 5.0. Versões: " + ", ".join(f"{k} ({v})" for k, v in list(AG["versoes"].items())[:6]) + ".",
            "Agentes antigos não têm TLS moderno, itens novos e correções de segurança.", "Atualizar agentes via automação (Ansible/GPO) priorizando os < 5.0; avaliar Agent 2.")
    nodes = PL.get("ha_nodes")
    if nodes is not None:
        add(D_HA, "Média", "Zabbix Server em HA nativo (cluster ativo/standby)", len(nodes) >= 2,
            f"{len(nodes)} nó(s): " + ", ".join(f"{n['name']} ({['standby', 'stopped', 'unavailable', 'active'][n['status']] if n['status'] < 4 else n['status']})" for n in nodes) + ".",
            "Falha do servidor único interrompe toda a coleta, alertas e escalonamentos.", "Habilitar HA nativo (HANodeName) com 2+ nós e banco com replicação.")
        if len(nodes) >= 2:
            bad = [n["name"] for n in nodes if n["status"] in (1, 2)]
            add(D_HA, "Alta", "Nós do cluster HA saudáveis", not bad, f"{len(bad)} nós parados/indisponíveis" + (f": {', '.join(bad)}" if bad else "") + ".",
                "Cluster sem standby saudável não faz failover.", "Recuperar nós parados ou removê-los do cluster.")
    else:
        add(D_HA, "Média", "Zabbix Server em HA nativo (cluster ativo/standby)", False, f"Versão {PL['versao']} não possui HA nativo (6.0+).",
            "Falha do servidor único interrompe toda a coleta e alertas.", "Upgrade para 7.0 LTS e HA nativo, ou cluster externo (Pacemaker) documentado.")
    if pr:
        off = [p["name"] for p in pr if p["online"] is False]
        add(D_HA, "Alta", "Proxies online", not off, f"{len(off)} de {len(pr)} proxies sem comunicação" + (f": {', '.join(off[:5])}" if off else "") + ".",
            "Hosts atrás de proxy offline ficam sem coleta e sem alerta.", "Restabelecer os proxies e criar trigger de 'proxy last seen' com escalonamento.")
        if ver >= (7, 0) and len(pr) >= 2:
            ng = len(PL.get("proxy_groups") or [])
            add(D_HA, "Baixa", "Proxy groups (balanceamento/failover)", ng > 0, f"{ng} proxy groups para {len(pr)} proxies.",
                "Falha de um proxy deixa seus hosts sem coleta até intervenção manual.", "Agrupar proxies por site em proxy groups (7.0+) com min_online ≥ 1.")
    add(D_CAP, "Alta", "Self-monitoring do Zabbix Server (template de saúde)", bool(srv),
        f"Itens internos do server {'encontrados em ' + srv['host'] if srv else 'não encontrados'} ({I.get('itens_desatualizados', 0)} itens internos desatualizados).",
        "Sem self-monitoring, saturação de processos, caches e fila só aparece quando a coleta já parou.",
        "Vincular 'Zabbix server health' ao host do server e 'Zabbix proxy health' a cada proxy, com alertas.")
    if srv:
        q = srv.get("queue_10m")
        if q is not None:
            lim_q = max(50, 0.001 * IT["habilitados"])
            add(D_CAP, "Alta", "Fila de coleta (itens atrasados > 10 min)", q <= lim_q, f"{num(q)} itens atrasados > 10 min (limite {num(lim_q)}).",
                "Itens atrasados geram alertas atrasados ou falsos 'nodata'.", "Investigar pollers/proxies saturados e hosts inalcançáveis; distribuir carga em proxies.")
        busy = {k: v for k, v in srv["processos"].items() if v > 75}
        if srv["processos"]:
            add(D_CAP, "Alta", "Processos internos do server < 75% de ocupação", not busy,
                f"{len(busy)} de {len(srv['processos'])} tipos de processo > 75%: " + (", ".join(f"{k} {v}%" for k, v in sorted(busy.items(), key=lambda kv: -kv[1])[:6]) or "nenhum") + ".",
                "Processo saturado atrasa coleta, cálculo de triggers ou envio de alertas.", "Aumentar Start<Processo> no zabbix_server.conf ou mover coleta para proxies.")
        full = {k: v for k, v in srv["caches"].items() if v > 75}
        if srv["caches"]:
            add(D_CAP, "Alta", "Caches do server com folga (< 75%)", not full,
                f"{len(full)} caches > 75%: " + (", ".join(f"{k} {v}%" for k, v in full.items()) or "nenhum") + ".",
                "Cache cheio degrada desempenho e pode parar a gravação de dados.", "Aumentar CacheSize/HistoryCacheSize/ValueCacheSize/TrendCacheSize conforme o cache saturado.")
        if srv.get("vcache_lowmem") is not None:
            add(D_CAP, "Média", "Value cache fora do modo low-memory", srv["vcache_lowmem"] == 0, f"Modo do value cache: {'low-memory' if srv['vcache_lowmem'] else 'normal'}.",
                "Em low-memory o server consulta o banco a cada cálculo de trigger, degradando o desempenho.", "Aumentar ValueCacheSize.")
        if srv.get("preproc_queue") is not None:
            add(D_CAP, "Baixa", "Fila de pré-processamento sob controle", srv["preproc_queue"] < 1000, f"{num(srv['preproc_queue'])} valores na fila de pré-processamento.",
                "Fila crescente indica gargalo de CPU de pré-processamento.", "Aumentar StartPreprocessors e revisar scripts JS pesados.")
    prs = I.get("proxies") or []
    if prs:
        hot = [p["host"] for p in prs if any(v > 75 for v in p["processos"].values()) or any(v > 75 for v in p["caches"].values())]
        add(D_CAP, "Média", "Proxies sem saturação (processos/caches < 75%)", not hot, f"{len(hot)} de {len(prs)} proxies com self-monitoring saturado" + (f": {', '.join(hot[:5])}" if hot else "") + ".",
            "Proxy saturado atrasa e perde dados dos hosts que atende.", "Ajustar Start*Pollers/caches do proxy ou redistribuir hosts.")
    if IT["habilitados"]:
        add(D_CAP, "Média", "Itens com intervalo agressivo (< 60s) controlados", pct(IT["agressivos"], IT["habilitados"]) <= 5,
            f"{num(IT['agressivos'])} de {num(IT['habilitados'])} itens com intervalo < 60s ({pct(IT['agressivos'], IT['habilitados'])}%).",
            "Intervalos curtos multiplicam NVPS, I/O de banco e custo de infraestrutura sem ganho proporcional.", "Padronizar 1m–5m; usar < 60s só em itens críticos justificados.")
    HK = PL.get("housekeeping") or {}
    if HK:
        hk_on = str(HK.get("hk_history_mode")) == "1" and str(HK.get("hk_trends_mode")) == "1"
        add(D_HK, "Alta", "Housekeeping de histórico e trends habilitado", hk_on,
            f"Histórico: {'on' if str(HK.get('hk_history_mode')) == '1' else 'off'} · trends: {'on' if str(HK.get('hk_trends_mode')) == '1' else 'off'}"
            + (f" · override global de histórico {HK.get('hk_history')}" if str(HK.get("hk_history_global")) == "1" else "") + ".",
            "Sem limpeza o banco cresce sem limite até esgotar disco e degradar consultas.", "Habilitar housekeeping (ou particionamento/TimescaleDB com políticas de retenção).")
        add(D_HK, "Baixa", "Retenção de eventos/problemas definida", str(HK.get("hk_events_mode")) == "1",
            f"Housekeeping de eventos: {'on' if str(HK.get('hk_events_mode')) == '1' else 'off'} (trigger events {HK.get('hk_events_trigger', '?')}).",
            "Tabelas de eventos e problemas crescem indefinidamente.", "Definir retenção de eventos (ex.: 365d trigger, 7d internos).")
        if str(HK.get("compression_availability")) == "1":
            add(D_HK, "Baixa", "Compressão TimescaleDB ativa", str(HK.get("compression_status")) == "1", f"Compressão: {'on' if str(HK.get('compression_status')) == '1' else 'off'}.",
                "Sem compressão o histórico ocupa 5–10x mais disco.", "Habilitar compressão (compress older than 7d).")
    if IT["habilitados"] and str(HK.get("hk_history_global")) != "1":
        add(D_HK, "Média", "Histórico de itens ≤ 90 dias", pct(IT["hist_longo"], IT["habilitados"]) <= 10,
            f"{num(IT['hist_longo'])} itens com histórico > 90 dias ({pct(IT['hist_longo'], IT['habilitados'])}%).",
            "Histórico longo infla o banco; trends já guardam min/máx/média horária para longo prazo.", "Reduzir histórico para 7–31d e manter trends 365d+.")

    # ---------------- Cobertura de monitoramento ---------------- #
    if nm:
        un = [h for h in mon if h["avail"] == 2]
        add(D_HOST, "Alta", "Hosts monitorados disponíveis", pct(len(un), nm) <= 5,
            f"{len(un)} de {nm} hosts monitorados com interface indisponível ({pct(len(un), nm)}%).",
            "Host indisponível não coleta: falhas reais passam despercebidas e pollers ficam ocupados.", "Corrigir conectividade/credenciais ou desabilitar hosts descomissionados.")
        if ver >= (7, 0):
            aa = [h for h in mon if h["active_avail"] == 2]
            add(D_HOST, "Média", "Agentes ativos (active checks) comunicando", pct(len(aa), nm) <= 5, f"{len(aa)} hosts com active checks indisponíveis.",
                "Itens ativos param sem erro aparente na interface passiva.", "Revisar ServerActive/hostname nos agentes e firewall para a porta 10051.")
        nt = [h for h in mon if not h["templates"] and not h["discovered"]]
        add(D_TPL, "Média", "Hosts com template vinculado", pct(len(nt), nm) <= 5, f"{len(nt)} de {nm} hosts sem template ({pct(len(nt), nm)}%).",
            "Configuração manual por host gera monitoração inconsistente e difícil de manter.", "Vincular templates padrão por papel (SO, banco, web) via grupos/autoregistro.")
        ntr = [h for h in mon if h.get("trig_hab", h["triggers"]) == 0]
        add(D_HOST, "Média", "Hosts com triggers (geram alerta)", pct(len(ntr), nm) <= 5, f"{len(ntr)} de {nm} hosts monitorados sem trigger habilitada ({pct(len(ntr), nm)}%).",
            "Host só coleta métricas: nenhum alerta é gerado em falha.", "Vincular templates com triggers ou criar triggers mínimas (disponibilidade, CPU, disco, memória).")
        tg = [h for h in mon if h["tags"]]
        add(D_HOST, "Média", "Hosts classificados com tags", pct(nm - len(tg), nm) <= 20, f"{nm - len(tg)} de {nm} hosts sem tag ({pct(nm - len(tg), nm)}%).",
            "Sem tags (ambiente, serviço, time) não há roteamento de alertas, filtros nem correlação.", "Padronizar tags de host: env, service, owner, criticidade; aplicar via autoregistro/LLD.")
        inv = sum(1 for h in mon if h["inventory"])
        add(D_HOST, "Baixa", "Inventário de hosts habilitado", pct(inv, nm) >= 50, f"{inv} de {nm} hosts com inventário habilitado.",
            "Sem inventário não há visão de SO, hardware e localização para operação.", "Definir inventory mode 'Automatic' como padrão.")
    dis = len(hosts) - nm
    if hosts:
        add(D_HOST, "Baixa", "Hosts desabilitados sob controle", pct(dis, len(hosts)) <= 10, f"{dis} de {len(hosts)} hosts desabilitados ({pct(dis, len(hosts))}%).",
            "Hosts desabilitados acumulam configuração obsoleta e poluem relatórios.", "Revisar e excluir hosts descomissionados.")
    tpls = d["templates_resumo"]
    if tpls.get("vendor_desatualizados") is not None:
        add(D_TPL, "Média", "Templates oficiais atualizados", tpls["vendor_desatualizados"] == 0,
            f"{tpls['vendor_desatualizados']} templates oficiais em uso com versão anterior à do server.",
            "Templates antigos não trazem correções de itens/triggers nem novas métricas.", "Importar a versão atual dos templates oficiais (git.zabbix.com) e revalidar customizações.")
    add(D_TPL, "Baixa", "Sem templates legados (pré-5.4) em uso", tpls["legados_em_uso"] == 0, f"{tpls['legados_em_uso']} templates 'Template ...' (nomenclatura pré-5.4) vinculados.",
        "Templates legados usam chaves e triggers depreciadas.", "Migrar para os templates 'by Zabbix agent/HTTP/SNMP' atuais.")
    if tpls.get("custom_sem_uso") is not None:
        add(D_TPL, "Baixa", "Templates customizados em uso", tpls["custom_sem_uso"] == 0, f"{tpls['custom_sem_uso']} de {tpls['custom']} templates customizados sem vínculo.",
            "Templates órfãos confundem a governança da configuração.", "Excluir/arquivar templates customizados sem uso.")
    if IT["habilitados"]:
        add(D_DATA, "Alta", "Itens não suportados", pct(IT["nao_suportados"], IT["habilitados"]) <= 2,
            f"{num(IT['nao_suportados'])} de {num(IT['habilitados'])} itens habilitados não suportados ({pct(IT['nao_suportados'], IT['habilitados'])}%). "
            + ("Erro mais comum: " + IT["erros"][0][0] if IT["erros"] else ""),
            "Item não suportado é uma lacuna silenciosa: a métrica não existe e suas triggers nunca disparam.", "Tratar por erro mais frequente (permissão, chave, timeout) e desabilitar o que não se aplica.")
    if LL["habilitadas"]:
        add(D_DATA, "Média", "Regras de LLD funcionando", pct(LL["nao_suportadas"], LL["habilitadas"]) <= 5,
            f"{LL['nao_suportadas']} de {LL['habilitadas']} regras de LLD não suportadas.",
            "LLD quebrada não descobre novos discos, interfaces e serviços: cobertura degrada com o tempo.", "Corrigir as regras com erro e revisar filtros/macros de LLD.")
    add(D_DATA, "Baixa", "Ação interna para itens/LLD/triggers não suportados", AL["acoes_internas_hab"] > 0,
        f"{AL['acoes_internas_hab']} ações de eventos internos habilitadas.", "Ninguém é avisado quando a coleta quebra.",
        "Criar ação de eventos internos notificando o time de plataforma (resumo diário).")
    add(D_SYN, "Média", "Monitoração web/sintética (web scenarios)", SY["web_hab"] > 0, f"{SY['web_hab']} web scenarios habilitados em hosts monitorados.",
        "Sem verificação sintética, indisponibilidade de aplicação só é percebida pelo usuário.", "Criar web scenarios/HTTP agent para URLs e jornadas críticas (login, checkout, APIs).")
    if SY["servicos"] is not None:
        add(D_SYN, "Baixa", "Serviços de negócio e SLA", (SY["servicos"] or 0) > 0 and (SY["slas"] or 0) > 0, f"{SY['servicos']} serviços e {SY['slas']} SLAs configurados.",
            "Sem árvore de serviços não há visão de impacto no negócio nem relatório de SLA.", "Modelar serviços de negócio por tags de problema e criar SLAs.")

    # ---------------- Qualidade de alertas ---------------- #
    te = TR["habilitadas"]
    if te:
        add(D_TRG, "Média", "Triggers classificadas por severidade", pct(TR["nao_classificadas"], te) <= 5, f"{TR['nao_classificadas']} de {te} triggers 'Não classificada'.",
            "Sem severidade, escalonamento e priorização não funcionam.", "Classificar triggers (Informação→Desastre) alinhado à matriz de impacto do ITSM.")
        add(D_TRG, "Média", "Triggers sem erro de avaliação", pct(TR["desconhecidas"], te) <= 2, f"{TR['desconhecidas']} triggers em estado desconhecido (erro de expressão/dados).",
            "Trigger em estado desconhecido nunca dispara.", "Corrigir expressões e itens dependentes das triggers com erro.")
        add(D_TRG, "Baixa", "Dependências entre triggers (evita tempestade de alertas)", TR["com_dependencia"] > 0, f"{TR['com_dependencia']} triggers com dependência.",
            "Queda de um link/switch gera centenas de alertas filhos em vez de um.", "Criar dependências: disponibilidade do host → serviços; rede/proxy → hosts.")
        add(D_TRG, "Baixa", "Triggers com tags (roteamento/correlação)", pct(TR["com_tags"], te) >= 50, f"{TR['com_tags']} de {te} triggers com tags ({pct(TR['com_tags'], te)}%).",
            "Sem tags não há correlação de eventos nem roteamento por serviço/time.", "Padronizar tags de trigger (scope, component, service).")
    add(D_PROB, "Alta", "Problemas High/Disaster reconhecidos em até 24h", PR["high_disaster_sem_ack_24h"] == 0,
        f"{PR['high_disaster']} problemas High/Disaster abertos; {PR['high_disaster_sem_ack_24h']} sem reconhecimento há mais de 24h.",
        "Problema crítico sem dono indica alerta ignorado ou ruído normalizado.", "Definir dono e SLA de reconhecimento; tratar ou ajustar as triggers recorrentes.")
    if PR["abertos"]:
        add(D_PROB, "Média", "Problemas abertos há mais de 30 dias", pct(PR["mais_30d"], PR["abertos"]) <= 10,
            f"{PR['mais_30d']} de {PR['abertos']} problemas abertos há mais de 30 dias ({pct(PR['mais_30d'], PR['abertos'])}%).",
            "Problemas eternos viram paisagem e escondem incidentes novos.", "Resolver a causa, ajustar limiar ou desabilitar triggers sem ação.")
    if PR["sev3_mais"]:
        add(D_PROB, "Média", "Problemas relevantes reconhecidos (ack)", pct(PR["sev3_ack"], PR["sev3_mais"]) >= 50,
            f"{PR['sev3_ack']} de {PR['sev3_mais']} problemas Média+ reconhecidos ({pct(PR['sev3_ack'], PR['sev3_mais'])}%).",
            "Sem ack não há rastreabilidade de quem está tratando.", "Tornar ack obrigatório no processo de on-call (ou integrar com ITSM).")
    if EV["total"] >= 50 and EV["top_triggers"]:
        top = EV["top_triggers"][0]
        add(D_NOISE, "Média", "Ruído de alertas concentrado", pct(top["disparos"], EV["total"]) < 20,
            f"{num(EV['total'])} problemas em {days}d ({EV['por_dia']}/dia); a trigger mais frequente (\"{clip(top['trigger'], 60)}\") responde por {pct(top['disparos'], EV['total'])}%.",
            "Alertas repetitivos geram fadiga e reduzem a confiança no monitoramento.", "Ajustar limiares/histerese, usar funções de janela (min/avg) e tratar causa raiz recorrente.")
    if te:
        add(D_NOISE, "Média", "Triggers em flapping", pct(EV["flapping_total"], te) <= 2,
            f"{EV['flapping_total']} triggers com ≥ 10 disparos e duração mediana < 10 min em {days}d.",
            "Flapping gera notificações em rajada sem incidente real.", "Adicionar histerese (expressão de recuperação) e avaliar janelas (ex.: avg(5m)).")
    if EV["resolvidos"] >= 20:
        add(D_NOISE, "Baixa", "Problemas de curta duração (< 5 min)", pct(EV["curta_duracao"], EV["resolvidos"]) <= 30,
            f"{pct(EV['curta_duracao'], EV['resolvidos'])}% dos problemas resolvidos duraram menos de 5 minutos.",
            "Alertas que se resolvem sozinhos raramente exigem ação humana.", "Aumentar a janela de avaliação ou atrasar a notificação (escalonamento step 2).")

    # ---------------- Resposta e operação ---------------- #
    add(D_NOTIF, "Alta", "Ações de trigger habilitadas com notificação", AL["acoes_com_mensagem"] > 0,
        f"{AL['acoes_trigger_hab']} de {AL['acoes_trigger']} ações de trigger habilitadas; {AL['acoes_com_mensagem']} enviam mensagem.",
        "Problemas são detectados mas ninguém é notificado.", "Criar ações por severidade/tag de serviço com destinatários por time.")
    add(D_NOTIF, "Alta", "Usuários com media de notificação ativa", AL["usuarios_com_media"] > 0,
        f"{AL['usuarios_com_media']} usuários com media ativa · media types habilitados: {AL['media_types_hab']} ("
        + ", ".join(f"{k} {v}" for k, v in AL["media_por_tipo"].items()) + ").",
        "Ação sem destinatário com media não entrega nada.", "Cadastrar media (e-mail/webhook) para usuários/grupos de on-call.")
    A_ = AL["alertas"]
    if A_["total"]:
        add(D_NOTIF, "Alta", "Notificações entregues sem falha", pct(A_["falhas"], A_["total"]) <= 2,
            f"{num(A_['falhas'])} de {num(A_['total'])} notificações falharam em {days}d ({pct(A_['falhas'], A_['total'])}%). "
            + ("Erro mais comum: " + A_["erros"][0][0] if A_["erros"] else ""),
            "Alerta que não chega equivale a não ter monitoramento.", "Corrigir media types com falha (SMTP/auth/URL do webhook) e alertar sobre falhas de envio.")
    if AL["acoes_com_mensagem"]:
        add(D_NOTIF, "Média", "Escalonamento configurado", AL["acoes_com_escalonamento"] > 0, f"{AL['acoes_com_escalonamento']} ações com mais de um passo de escalonamento.",
            "Problema não tratado não sobe para o próximo nível.", "Configurar passos: on-call → líder técnico → gestão (ex.: 15/30/60 min).")
        add(D_NOTIF, "Baixa", "Notificação de recuperação", pct(AL["acoes_com_recuperacao"], AL["acoes_trigger_hab"]) >= 80,
            f"{AL['acoes_com_recuperacao']} de {AL['acoes_trigger_hab']} ações com operação de recuperação.",
            "Time não sabe quando o problema foi normalizado.", "Adicionar recovery operations às ações.")
        add(D_MAINT, "Baixa", "Ações pausam problemas suprimidos (manutenção)", AL["acoes_pausam_suprimidos"] == AL["acoes_trigger_hab"],
            f"{AL['acoes_pausam_suprimidos']} de {AL['acoes_trigger_hab']} ações pausam operações durante manutenção.",
            "Janelas de manutenção ainda disparam notificações.", "Marcar 'Pause operations for suppressed problems' nas ações.")
    add(D_INT, "Média", "Integração com ITSM/on-call (webhook)", bool(AL["integracoes_oncall"]),
        f"Integrações detectadas: {', '.join(AL['integracoes_oncall']) or 'nenhuma'} · webhooks habilitados: {len(AL['webhooks_hab'])}.",
        "Sem integração, incidentes não são abertos automaticamente e o acionamento 24x7 depende de e-mail.",
        "Configurar webhook para ITSM (ServiceNow/Jira/GLPI) e on-call (PagerDuty/Opsgenie/Teams).")
    for t in d["meta"]["expected_integrations"]:
        hit = [n for n in AL["integracoes_oncall"] + (AL.get("connectors") or []) + AL["webhooks_hab"] if t in (n or "").lower()]
        add(D_INT, "Média", f"Integração Zabbix ↔ {t.title()} detectada", bool(hit),
            ("Media types/connectors: " + ", ".join(sorted(set(hit))) + ".") if hit else "Nenhum media type ou connector com referência.",
            f"Eventos do Zabbix não chegam ao {t.title()}: sem correlação com o restante da operação.", f"Configurar o media type/webhook oficial do {t.title()} e testar o fluxo ponta a ponta.")
    if AL.get("connectors") is not None:
        add(D_INT, "Baixa", "Streaming de dados/eventos (connectors)", bool(AL["connectors"]), f"{len(AL['connectors'])} connectors ativos.",
            "Dados ficam presos ao Zabbix, sem correlação na plataforma central de observabilidade.", "Avaliar connectors (6.4+) para exportar eventos/métricas para a plataforma central.")
    add(D_MAINT, "Baixa", "Janelas de manutenção vencidas removidas", not MT["expiradas"], f"{len(MT['expiradas'])} de {MT['total']} manutenções expiradas ainda cadastradas.",
        "Poluição da configuração e risco de reativação acidental.", "Remover janelas vencidas periodicamente.")
    if EV["reconhecidos"] >= 10:
        add(D_RESP, "Média", "MTTA mediano ≤ 30 min", (EV["mtta_mediana_min"] or 0) <= 30,
            f"MTTA mediano {num(EV['mtta_mediana_min'], 1)} min · P90 {num(EV['mtta_p90_min'], 1)} min ({EV['reconhecidos']} eventos reconhecidos em {days}d).",
            "Reconhecimento lento aumenta o tempo total de indisponibilidade.", "Definir SLA de ack por severidade e acompanhar em dashboard.")
    if EV["mttr_hi_mediana_min"] is not None:
        add(D_RESP, "Média", "MTTR mediano High/Disaster ≤ 60 min", EV["mttr_hi_mediana_min"] <= 60,
            f"MTTR mediano High/Disaster {num(EV['mttr_hi_mediana_min'], 1)} min · geral {num(EV['mttr_mediana_min'], 1)} min (P90 {num(EV['mttr_p90_min'], 1)} min).",
            "Problemas críticos longos impactam diretamente o negócio.", "Runbooks por trigger crítica, automação de remediação e postmortem dos recorrentes.")

    # ---------------- Segurança e governança ---------------- #
    if SE["guest_ativo"] is not None:
        add(D_IAM, "Alta", "Usuário guest desabilitado", not SE["guest_ativo"], f"guest {'com' if SE['guest_ativo'] else 'sem'} acesso ao frontend.",
            "Acesso anônimo expõe topologia, hosts e problemas.", "Manter guest no grupo 'Disabled' e frontend access desabilitado.")
        add(D_IAM, "Média", "Usuário 'Admin' padrão desabilitado ou renomeado", not SE["admin_padrao_ativo"],
            f"Usuário 'Admin' {'ativo' if SE['admin_padrao_ativo'] else 'inexistente/desabilitado'}.",
            "Conta padrão é o primeiro alvo de força bruta (credencial conhecida).", "Criar admins nominais e desabilitar/renomear 'Admin'.")
        if SE["usuarios_ativos"]:
            add(D_IAM, "Média", "Super admins restritos", SE["super_admins"] <= max(5, round(0.1 * SE["usuarios_ativos"])),
                f"{SE['super_admins']} super admins entre {SE['usuarios_ativos']} usuários ativos.",
                "Excesso de super admins amplia o raio de impacto de erro ou credencial vazada.", "Aplicar menor privilégio com roles e grupos por escopo de host group.")
    if SE["ldap"] is not None:
        ext = SE["ldap"] or SE["saml"]
        add(D_IAM, "Alta", "Autenticação centralizada (LDAP/SAML)", bool(ext), f"LDAP: {'sim' if SE['ldap'] else 'não'} · SAML: {'sim' if SE['saml'] else 'não'}.",
            "Contas locais não seguem desligamento de colaboradores nem política corporativa de senha.", "Integrar com AD/Entra ID (LDAP ou SAML SSO) e manter só contas de emergência locais.")
    if SE["mfa"] is not None:
        add(D_IAM, "Média", "MFA habilitado", SE["mfa"] and SE["grupos_mfa"] > 0, f"MFA {'habilitado' if SE['mfa'] else 'desabilitado'} · {SE['grupos_mfa']} grupos com MFA.",
            "Senha vazada dá acesso direto ao frontend.", "Habilitar MFA (TOTP/Duo) nos grupos com acesso ao frontend (ou via IdP SAML).")
    if SE["senha_min"] is not None and not (SE["ldap"] or SE["saml"]):
        add(D_IAM, "Média", "Política de senha forte (local)", SE["senha_min"] >= 12 and (SE["senha_regras"] or 0) >= 2,
            f"Tamanho mínimo {SE['senha_min']} · {SE['senha_regras']} regras de complexidade.", "Senhas fracas facilitam força bruta.", "Mínimo 12 caracteres + complexidade + bloqueio por tentativas.")
    if SE["tokens_ativos"]:
        add(D_IAM, "Média", "API tokens com expiração", SE["tokens_sem_expiracao"] == 0, f"{SE['tokens_sem_expiracao']} de {SE['tokens_ativos']} tokens ativos sem data de expiração.",
            "Token sem expiração vazado dá acesso permanente à API.", "Definir expiração (≤ 1 ano), rotacionar e guardar em cofre.")
        add(D_IAM, "Baixa", "API tokens sem uso revogados", SE["tokens_sem_uso_90d"] == 0, f"{SE['tokens_sem_uso_90d']} tokens ativos sem uso há mais de 90 dias.",
            "Credenciais órfãs aumentam a superfície de ataque.", "Desabilitar/excluir tokens sem uso.")
    if SE["usuarios"]:
        add(D_IAM, "Baixa", "Debug mode desligado nos grupos", not SE["grupos_debug"], f"{len(SE['grupos_debug'])} grupos com debug mode: {', '.join(SE['grupos_debug'][:5]) or '—'}.",
            "Debug mode expõe SQL/consultas no frontend e degrada desempenho.", "Desabilitar debug mode.")
    ag_h = [h for h in mon if h["agent_iface"]]
    if ag_h:
        enc = sum(1 for h in ag_h if h["tls"])
        add(D_ENC, "Média", "Criptografia agente ↔ server/proxy (PSK/certificado)", pct(enc, len(ag_h)) >= 80,
            f"{enc} de {len(ag_h)} hosts com agente usando TLS ({pct(enc, len(ag_h))}%).",
            "Tráfego do agente em texto claro permite interceptação e injeção de dados.", "Habilitar TLS PSK por host (ou certificado) e exigir conexão criptografada.")
    if pr:
        pe = sum(1 for p in pr if p["tls"])
        add(D_ENC, "Alta", "Proxies com comunicação criptografada", pe == len(pr), f"{pe} de {len(pr)} proxies com TLS obrigatório.",
            "Proxy em texto claro trafega dados de muitos hosts e configuração do server.", "Configurar TLS PSK/certificado em todos os proxies.")
    ex = SE["macros_globais_expostas"]
    add(D_ENC, "Alta", "Segredos em macros protegidos (Secret text/Vault)", not ex and SE["macros_host_expostas"] == 0,
        f"{len(ex)} macros globais e {SE['macros_host_expostas']} macros de host/template com nome de segredo em texto plano"
        + (f": {', '.join(ex[:5])}" if ex else "") + f" · {SE['macros_secret']} macros já como secret/vault.",
        "Senhas legíveis por qualquer usuário com acesso de leitura à configuração.", "Converter para 'Secret text' ou integrar HashiCorp Vault/CyberArk.")
    if SE["scripts_total"]:
        add(D_ENC, "Média", "Scripts globais restritos", not SE["scripts_risco"], f"{len(SE['scripts_risco'])} scripts executados no server/proxy liberados para todos os grupos"
            + (f": {', '.join(SE['scripts_risco'][:5])}" if SE["scripts_risco"] else "") + ".",
            "Execução remota de comandos por qualquer usuário do frontend.", "Restringir scripts por grupo de usuários/host group e EnableGlobalScripts=0 quando não usado.")
    if SE["audit_log"] is not None:
        add(D_AUD, "Média", "Audit log habilitado", SE["audit_log"], f"Audit log {'habilitado' if SE['audit_log'] else 'desabilitado'}.",
            "Sem trilha de quem alterou configuração, usuários e permissões.", "Habilitar audit log.")
    if SE["audit_retencao_d"] is not None:
        add(D_AUD, "Baixa", "Retenção do audit log ≥ 365 dias", SE["audit_retencao_d"] >= 365, f"Retenção configurada: {SE['audit_retencao_d']} dias.",
            "Retenção curta impede investigação e atendimento a auditorias.", "Ajustar retenção do audit para 365 dias.")
    return out


def score(checks: list[Check], key: str = "domain") -> tuple[dict[str, int], int]:
    acc: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for c in checks:
        if c.passed is None:
            continue
        w = SEV_W[c.severity]
        k = getattr(c, key)
        acc[k][1] += w
        acc[k][0] += w if c.passed else 0
    dom = {k: pct(a, b) for k, (a, b) in acc.items() if b}
    ta, tb = sum(a for a, _ in acc.values()), sum(b for _, b in acc.values())
    return dom, pct(ta, tb)


def score_actions(checks: list[Check], pillar: str) -> list[dict]:
    """Para cada lacuna do pilar: score do pilar e global se só ela fosse resolvida, e o acumulado resolvendo em ordem de ganho."""
    pil0, _ = score(checks, "pillar")
    _, ov0 = score(checks)

    def sim(fixed: set[int]) -> tuple[int, int]:
        cs = [replace(c, passed=True) if i in fixed else c for i, c in enumerate(checks)]
        p, _ = score(cs, "pillar")
        _, o = score(cs)
        return p.get(pillar, 0), o

    gaps = [i for i, c in enumerate(checks) if c.pillar == pillar and c.passed is False]
    rows = []
    for i in gaps:
        p, o = sim({i})
        rows.append({"idx": i, "check": checks[i], "pilar_de": pil0.get(pillar, 0), "pilar_para": p, "global_de": ov0, "global_para": o})
    rows.sort(key=lambda r: (-(r["global_para"] - r["global_de"]), -(r["pilar_para"] - r["pilar_de"]), SEV_ORDER[r["check"].severity]))
    fixed: set[int] = set()
    for r in rows:
        fixed.add(r["idx"])
        r["pilar_acum"], r["global_acum"] = sim(fixed)
    return rows


def level(sc: int) -> str:
    return "Inicial" if sc < 40 else "Em desenvolvimento" if sc < 65 else "Estruturado" if sc < 85 else "Otimizado"


# --------------------------------------------------------------------------- #
# Relatório HTML
# --------------------------------------------------------------------------- #

CSS = """
:root{--bg:#f6f7f9;--card:#fff;--tx:#1b1f24;--mut:#667085;--bd:#e4e7ec;--ok:#12805c;--warn:#b54708;--bad:#c01048;--acc:#d40000}
@media(prefers-color-scheme:dark){:root{--bg:#0f1115;--card:#171a21;--tx:#e8eaed;--mut:#9aa3b2;--bd:#262b36;--ok:#3ddc97;--warn:#ffb020;--bad:#ff6b8b;--acc:#ff6b6b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1120px;margin:0 auto;padding:32px 20px 64px}h1{margin:0 0 4px;font-size:28px}h2{margin:40px 0 14px;font-size:20px}h3{margin:18px 0 8px;font-size:15px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
.sub{color:var(--mut)}.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:18px 20px}
.grid{display:grid;gap:14px}.g4{grid-template-columns:repeat(auto-fit,minmax(190px,1fr))}.g2{grid-template-columns:repeat(auto-fit,minmax(340px,1fr))}
.kpi b{display:block;font-size:28px;line-height:1.2}.kpi span{color:var(--mut);font-size:13px}
.hero{display:flex;gap:28px;align-items:center;flex-wrap:wrap}.ring{--p:0;--c:var(--ok);width:130px;height:130px;border-radius:50%;background:conic-gradient(var(--c) calc(var(--p)*3.6deg),var(--bd) 0);display:grid;place-items:center;flex:none}
.ring i{font-style:normal;width:98px;height:98px;border-radius:50%;background:var(--card);display:grid;place-items:center;font-size:30px;font-weight:700}
.bar{height:8px;background:var(--bd);border-radius:6px;overflow:hidden}.bar i{display:block;height:100%}
.row{display:grid;grid-template-columns:220px 1fr 44px;gap:12px;align-items:center;margin:9px 0}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:9px 10px;border-bottom:1px solid var(--bd);vertical-align:top}th{color:var(--mut);font-weight:600;font-size:12px;text-transform:uppercase}
.badge{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;white-space:nowrap}
.Alta,.nao{background:color-mix(in srgb,var(--bad) 16%,transparent);color:var(--bad)}.Média,.parcial{background:color-mix(in srgb,var(--warn) 16%,transparent);color:var(--warn)}
.Baixa,.nd{background:var(--bd);color:var(--mut)}.sim{background:color-mix(in srgb,var(--ok) 16%,transparent);color:var(--ok)}
.zs{color:#1b1f24}ul{margin:6px 0;padding-left:20px}.mut{color:var(--mut)}.road{border-left:4px solid var(--bd)}
@media print{body{background:#fff}.card{break-inside:avoid}}
"""


def esc(x: Any) -> str:
    return html.escape(str(x))


def color(sc: int) -> str:
    return "var(--ok)" if sc >= 75 else "var(--warn)" if sc >= 50 else "var(--bad)"


def table(headers: list[str], rows: list[list[Any]], raw: bool = False) -> str:
    if not rows:
        return '<p class="mut">Sem dados.</p>'
    th = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{c if raw else esc(c)}</td>" for c in r) + "</tr>" for r in rows)
    return f"<table><thead><tr>{th}</tr></thead><tbody>{body}</tbody></table>"


def badge(txt: str, cls: str | None = None) -> str:
    return f'<span class="badge {cls or txt}">{esc(txt)}</span>'


def zsev_badge(name: str) -> str:
    code = next((k for k, v in ZSEV.items() if v == name), 0)
    return f'<span class="badge zs" style="background:{ZSEV_HEX[code]}">{esc(name)}</span>'


def dict_rows(d: dict | None) -> list[list[Any]]:
    return [[k, v] for k, v in sorted((d or {}).items(), key=lambda kv: -kv[1] if isinstance(kv[1], (int, float)) else 0)]


def cov_badge(n: int, t: int) -> str:
    p = pct(n, t)
    return badge(f"{n}/{t} · {p}%", "sim" if p >= 80 else "parcial" if p >= 40 else "nao")


def yn(v: Any) -> str:
    return "N/D" if v is None else "sim" if v else "não"


def capability_items(d: dict) -> list[tuple[str, Any]]:
    PL, AL, SY, SE, LL = d["platform"], d["alerting"], d["synthetic"], d["security"], d["lld"]
    I = PL.get("interno") or {}
    nodes, pg = PL.get("ha_nodes"), PL.get("proxy_groups")
    hk = PL.get("housekeeping") or {}
    items = [
        ("Nós HA do server", None if nodes is None else len(nodes)), ("Proxies", len(PL["proxies"])), ("Proxy groups", None if pg is None else len(pg)),
        ("Self-monitoring do server", 1 if I.get("server") else 0), ("Self-monitoring de proxies", len(I.get("proxies") or [])),
        ("Web scenarios", SY["web_hab"]), ("Regras de LLD", LL["habilitadas"]), ("Network discovery", SY["discovery_hab"]),
        ("Ações de trigger", AL["acoes_trigger_hab"]), ("Ações com escalonamento", AL["acoes_com_escalonamento"]),
        ("Ações de eventos internos", AL["acoes_internas_hab"]), ("Autoregistro de agentes", AL["acoes_autoregistro_hab"]),
        ("Webhooks", len(AL["webhooks_hab"])), ("Integrações ITSM/on-call", len(AL["integracoes_oncall"])),
        ("Serviços de negócio", SY["servicos"]), ("SLAs", SY["slas"]), ("Dashboards", SY["dashboards"]), ("Relatórios agendados", SY["relatorios_agendados"]),
        ("Connectors (streaming)", None if AL.get("connectors") is None else len(AL["connectors"])),
        ("LDAP / SAML", None if SE["ldap"] is None else int(bool(SE["ldap"] or SE["saml"]))), ("MFA", None if SE["mfa"] is None else int(bool(SE["mfa"]))),
        ("Hosts com TLS", sum(1 for h in d["hosts"] if h["monitored"] and h["tls"])), ("Zabbix Agent 2", d["agents"]["agent2"]),
        ("Macros secret/vault", SE["macros_secret"]),
        ("Compressão TimescaleDB", None if str(hk.get("compression_availability")) != "1" else int(str(hk.get("compression_status")) == "1")),
    ]
    return items


def capability_matrix(d: dict) -> list[list[Any]]:
    rows = []
    for name, n in capability_items(d):
        b = badge("N/D", "nd") if n is None else badge("Em uso", "sim") if n > 0 else badge("Não detectado", "nao")
        rows.append([esc(name), "-" if n is None else num(n), b])
    return rows


def report_ctx(d: dict, checks: list[Check], pil: dict[str, int], overall: int) -> dict:
    """Dados derivados compartilhados por HTML, PDF e PowerPoint."""
    porder = {p: i for i, p in enumerate(PILLARS)}
    fails = sorted((c for c in checks if c.passed is False), key=lambda c: (SEV_ORDER[c.severity], porder.get(c.pillar, 9)))
    IT, TR, PR, A_ = d["items"], d["triggers"], d["problems"], d["alerting"]["alertas"]
    mon = [h for h in d["hosts"] if h["monitored"]]
    avail = sum(1 for h in mon if h["avail"] != 2)
    srv = (d["platform"].get("interno") or {}).get("server") or {}
    nvps = srv.get("nvps") if srv.get("nvps") is not None else IT["nvps_estimado"]
    kpis = [("Hosts monitorados", num(len(mon))), ("Itens habilitados", num(IT["habilitados"])), ("Triggers habilitadas", num(TR["habilitadas"])),
            ("NVPS" + ("" if srv.get("nvps") is not None else " (estimado)"), num(nvps, 1)), ("Hosts disponíveis", f"{pct(avail, len(mon))}%"),
            ("Itens não suportados", f"{pct(IT['nao_suportados'], IT['habilitados'])}%"), ("Problemas High/Disaster abertos", num(PR["high_disaster"])),
            ("Falhas de notificação", f"{pct(A_['falhas'], A_['total'])}%" if A_.get("total") else "N/D")]
    return {"fails": fails, "oks": [c for c in checks if c.passed], "high": [c for c in fails if c.severity == "Alta"],
            "evaluated": [c for c in checks if c.passed is not None], "n_mon": len(mon), "avail": avail, "nvps": nvps, "nvps_real": srv.get("nvps") is not None,
            "kpis": kpis, "worst": sorted(pil.items(), key=lambda kv: kv[1])[:2], "best": max(pil.items(), key=lambda kv: kv[1], default=None),
            "overall": overall, "pil": pil, "hy": d["hygiene"], "srv": srv}


def exec_summary(d: dict, x: dict, b: Callable[[Any], str] = lambda s: f"<b>{s}</b>", e: Callable[[Any], str] = esc) -> str:
    """Parágrafo do resumo executivo; `b` marca destaque e `e` escapa texto (HTML, PDF ou texto puro)."""
    M, PL, EV, HY, ov = d["meta"], d["platform"], d["events"], d["hygiene"], x["overall"]
    s = (f"O ambiente Zabbix {b(e(M['ambiente']))} (versão {b(e(PL['versao']))}, suporte {e(PL['suporte']['status'])}) monitora "
         f"{b(num(x['n_mon']))} hosts, {b(num(d['items']['habilitados']))} itens e {b(num(d['triggers']['habilitadas']))} triggers, "
         f"com {b(num(x['nvps'], 1))} valores por segundo" + ("" if x["nvps_real"] else " (estimado)") + ". "
         + "A maturidade de observabilidade é " + b(f"{ov}/100 ({level(ov)})") + "; os pilares mais frágeis são "
         + " e ".join(f"{b(e(k))} ({v})" for k, v in x["worst"]) + ". "
         + f"Foram identificadas {b(len(x['fails']))} lacunas, {b(len(x['high']))} de prioridade alta"
         + (": " + "; ".join(e(c.title.lower()) for c in x["high"][:4]) if x["high"] else "") + ". ")
    if EV["total"]:
        s += (f"Nos últimos {M['days']} dias houve {b(num(EV['total']))} problemas ({num(EV['por_dia'], 1)}/dia)"
              + (f", com MTTR mediano de {b(num(EV['mttr_mediana_min'], 1) + ' min')}" if EV["mttr_mediana_min"] is not None else "") + ". ")
    if HY["oportunidades"]:
        dp = HY.get("de_para") or []
        red = sum(r["reducao"] for r in dp)
        s += (f"Há {b(len(HY['oportunidades']))} oportunidades de higiene da configuração"
              + (f", que reduzem {b(num(red, 1) + ' NVPS')} ({pct(red, HY['nvps_base'])}% da carga de polling)" if red else "") + ".")
    return s


ROADMAP = (("Alta", "0 – 30 dias"), ("Média", "30 – 60 dias"), ("Baixa", "60 – 90 dias"))
PNOTE = "Pilares de maturidade de observabilidade (SRE); pontuação ponderada por criticidade (Alta=3, Média=2, Baixa=1)."


def platform_rows(d: dict, x: dict) -> list[list[Any]]:
    PL, srv, IT = d["platform"], x["srv"], d["items"]
    sp, nodes = PL["suporte"], PL.get("ha_nodes")
    st = ["standby", "stopped", "unavailable", "active"]
    return [["Versão", PL["versao"] + (" (LTS)" if sp["lts"] else "")],
            ["Suporte do fabricante", f"{sp['status']}" + (f" · completo até {sp['fim_completo']} · limitado até {sp['fim_limitado']}" if sp.get("fim_limitado") else "")],
            ["HA nativo", "N/D (< 6.0)" if nodes is None else ", ".join(f"{n['name']}: {st[n['status']] if n['status'] < 4 else n['status']}" for n in nodes) or "—"],
            ["NVPS (self-monitoring)", num(srv.get("nvps"), 1)], ["NVPS requerido (configuração)", num(srv.get("nvps_requerido"), 1)],
            ["NVPS estimado (itens de polling)", num(IT["nvps_estimado"], 1)], ["Fila > 10 min", num(srv.get("queue_10m"))],
            ["Fila total", num(srv.get("queue"))], ["Fila de pré-processamento", num(srv.get("preproc_queue"))],
            ["Value cache", "N/D" if srv.get("vcache_lowmem") is None else "low-memory" if srv["vcache_lowmem"] else "normal"],
            ["Proxies", f"{len(PL['proxies'])} ({sum(1 for p in PL['proxies'] if p['online'] is False)} offline)"]]


def build_report(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str) -> str:
    M, PL, IT, TR, PR, EV = d["meta"], d["platform"], d["items"], d["triggers"], d["problems"], d["events"]
    AL, SE, HY, LL = d["alerting"], d["security"], d["hygiene"], d["lld"]
    days = M["days"]
    x = report_ctx(d, checks, pil, overall)
    fails, oks, srv = x["fails"], x["oks"], x["srv"]
    summary = exec_summary(d, x)
    kpi_html = "".join(f'<div class="card kpi"><b>{esc(v)}</b><span>{esc(k)}</span></div>' for k, v in x["kpis"])

    def bars(items):
        return "".join(f'<div class="row"><span>{esc(k)}</span><div class="bar"><i style="width:{min(v, 100)}%;background:{color(v)}"></i></div><b>{v}</b></div>' for k, v in items)

    def busy_bars(items):
        return "".join(f'<div class="row"><span>{esc(k)}</span><div class="bar"><i style="width:{min(v, 100)}%;background:{color(100 - v)}"></i></div><b>{round(v)}%</b></div>' for k, v in items)

    pil_rows = []
    for p in PILLARS:
        cs = [c for c in checks if c.pillar == p and c.passed is not None]
        pil_rows.append([esc(p), f"<b style='color:{color(pil[p])}'>{pil[p]}</b>" if p in pil else "N/A", sum(1 for c in cs if c.passed),
                         sum(1 for c in cs if not c.passed), sum(1 for c in cs if not c.passed and c.severity == "Alta")])
    dom_by_p = "".join(
        f"<h3>{esc(p)}</h3>" + bars(sorted(((k, v) for k, v in dom.items() if any(c.domain == k and c.pillar == p for c in checks)), key=lambda kv: kv[1]))
        for p in PILLARS if any(c.pillar == p for c in checks))
    find_rows = [[badge(c.severity), esc(c.pillar), esc(c.domain), f"<b>{esc(c.title)}</b><br><span class='mut'>{esc(c.evidence)}</span>", esc(c.impact), esc(c.recommendation)] for c in fails]
    road = ""
    for sev, label in ROADMAP:
        items = [c for c in fails if c.severity == sev]
        if items:
            road += f'<div class="card road"><h3>{label} · prioridade {sev}</h3><ul>' + "".join(
                f"<li><span class='badge nd'>{esc(c.pillar)}</span> <b>{esc(c.title)}</b> — {esc(c.recommendation)}</li>" for c in items) + "</ul></div>"

    # 7 · Plataforma
    hosts_by_proxy = Counter(h["proxy"] for h in d["hosts"] if h["monitored"])
    prx_rows = [[esc(p["name"]), p["modo"], badge("online", "sim") if p["online"] else badge("offline", "nao") if p["online"] is False else badge("N/D", "nd"),
                 "-" if p["lastaccess_min"] is None else f"{p['lastaccess_min']} min", esc(p.get("versao") or "-"),
                 badge("sim", "sim") if p["tls"] else badge("não", "nao"), hosts_by_proxy.get(p["id"], 0)] for p in PL["proxies"]]
    procs = sorted((srv.get("processos") or {}).items(), key=lambda kv: -kv[1])[:16]
    plat_html = (f'<div class="grid g2"><div class="card"><h3>Server</h3>{table(["Item", "Valor"], platform_rows(d, x))}</div>'
                 f'<div class="card"><h3>Ocupação de processos (server)</h3>{busy_bars(procs) or "<p class=mut>Sem self-monitoring do server.</p>"}</div>'
                 f'<div class="card"><h3>Caches (% em uso)</h3>{table(["Cache", "Uso %"], dict_rows(srv.get("caches")))}</div>'
                 f'<div class="card"><h3>Proxies com self-monitoring</h3>{table(["Proxy", "Processo mais ocupado", "Cache mais cheio"], [[p["host"], max(p["processos"].items(), key=lambda kv: kv[1], default=("-", 0))[0] + " " + str(max(p["processos"].values(), default=0)) + "%", max(p["caches"].items(), key=lambda kv: kv[1], default=("-", 0))[0] + " " + str(max(p["caches"].values(), default=0)) + "%"] for p in (PL.get("interno") or {}).get("proxies", [])[:15]])}</div></div>'
                 f'<div class="card" style="margin-top:14px"><h3>Proxies</h3>{table(["Proxy", "Modo", "Estado", "Último contato", "Versão", "TLS", "Hosts"], prx_rows, raw=True)}</div>')
    # 8 · Cobertura
    cov_rows = [[esc(g), v["total"], v.get("monitorados", 0), cov_badge(v.get("disponiveis", 0), v.get("monitorados", 0)), cov_badge(v.get("com_template", 0), v.get("monitorados", 0)),
                 cov_badge(v.get("com_trigger", 0), v.get("monitorados", 0)), cov_badge(v.get("sem_nao_suportado", 0), v.get("monitorados", 0)),
                 cov_badge(v.get("com_tag", 0), v.get("monitorados", 0)), cov_badge(v.get("com_tls", 0), v.get("monitorados", 0))]
                for g, v in list(d["coverage"].items())[:40] if v.get("monitorados")]
    cov_html = (f'<div class="card">{table(["Capacidade", "Itens", "Situação"], capability_matrix(d), raw=True)}</div>'
                f'<h3>Cobertura por host group (top 40)</h3><div class="card">{table(["Host group", "Hosts", "Monitorados", "Disponíveis", "Com template", "Com trigger", "Sem item não suportado", "Com tag", "TLS"], cov_rows, raw=True)}'
                f'<p class="mut">Detalhe por host em cobertura_hosts.csv; por grupo em cobertura_grupos.csv.</p></div>'
                f'<div class="grid g2" style="margin-top:14px"><div class="card"><h3>Itens por tipo</h3>{table(["Tipo", "Itens"], dict_rows(IT["por_tipo"]))}</div>'
                f'<div class="card"><h3>Erros mais comuns em itens não suportados</h3>{table(["Erro", "Itens"], IT["erros"][:12])}</div>'
                f'<div class="card"><h3>LLD</h3>{table(["Item", "Valor"], [["Regras habilitadas", LL["habilitadas"]], ["Não suportadas", LL["nao_suportadas"]]] + [["Erro: " + k, v] for k, v in LL["erros"][:6]])}</div>'
                f'<div class="card"><h3>Versões de agente</h3>{table(["Versão", "Hosts"], dict_rows(d["agents"]["versoes"]))}<p class="mut">Agent 2: {d["agents"]["agent2"]} hosts.</p></div></div>')
    # 9 · Alertas
    top_rows = [[esc(clip(t["trigger"], 90)), esc(t["host"]), zsev_badge(t["sev"]), t["disparos"], num(t["mttr_mediana_min"], 1), num(t["mtta_mediana_min"], 1)] for t in EV["top_triggers"][:15]]
    old_rows = [[esc(clip(p["nome"], 90)), esc(p["host"]), zsev_badge(p["sev"]), p["dias"], "sim" if p["ack"] else "não"] for p in PR["mais_antigos"][:15]]
    sev_rows = [[zsev_badge(s), TR["por_severidade"].get(s, 0), PR["por_severidade"].get(s, 0), EV["por_severidade"].get(s, 0)] for s in ZSEV.values()]
    alr_html = ('<div class="grid g4">' +"".join(f'<div class="card kpi"><b>{esc(v)}</b><span>{esc(k)}</span></div>' for k, v in [
        (f"Problemas em {days}d", num(EV["total"])), ("Por dia", num(EV["por_dia"], 1)), ("MTTR mediano (min)", num(EV["mttr_mediana_min"], 1)),
        ("MTTA mediano (min)", num(EV["mtta_mediana_min"], 1)), ("Problemas abertos", num(PR["abertos"])), ("Abertos > 30 dias", num(PR["mais_30d"])),
        ("Triggers em flapping", num(EV["flapping_total"])), ("Curta duração (< 5 min)", f"{pct(EV['curta_duracao'], EV['resolvidos'])}%")]) + "</div>"
        f'<div class="card" style="margin-top:14px"><h3>Por severidade</h3>{table(["Severidade", "Triggers habilitadas", "Problemas abertos", f"Problemas em {days}d"], sev_rows, raw=True)}</div>'
        f'<div class="card" style="margin-top:14px"><h3>Triggers que mais dispararam ({days}d)</h3>{table(["Trigger", "Host", "Severidade", "Disparos", "MTTR mediano (min)", "MTTA mediano (min)"], top_rows, raw=True)}'
        f'<p class="mut">Lista completa em top_triggers.csv.' + (" Coleta de eventos truncada pelo limite diário (--max-events-per-day)." if EV["truncado"] else "") + '</p></div>'
        f'<div class="card" style="margin-top:14px"><h3>Problemas abertos mais antigos</h3>{table(["Problema", "Host", "Severidade", "Dias", "Ack"], old_rows, raw=True)}</div>')
    # 10 · Resposta
    A_ = AL["alertas"]
    act_rows = [["Ações de trigger (habilitadas/total)", "%s/%s" % (AL["acoes_trigger_hab"], AL["acoes_trigger"])], ["Com mensagem", AL["acoes_com_mensagem"]],
                ["Com escalonamento", AL["acoes_com_escalonamento"]], ["Com recuperação", AL["acoes_com_recuperacao"]], ["Com update (ack)", AL["acoes_com_update"]],
                ["Pausam suprimidos", AL["acoes_pausam_suprimidos"]], ["Ações de eventos internos", AL["acoes_internas_hab"]],
                ["Usuários com media ativa", AL["usuarios_com_media"]], ["Notificações em %sd" % days, num(A_.get("total"))], ["Falhas de envio", num(A_.get("falhas"))]]
    resp_html = (f'<div class="grid g2"><div class="card"><h3>Ações e notificação</h3>{table(["Item", "Valor"], act_rows)}</div>'
                 f'<div class="card"><h3>Media types em uso (usuários)</h3>{table(["Media type", "Usuários"], dict_rows(AL["media_em_uso"]))}<p class="mut">Integrações ITSM/on-call: {esc(", ".join(AL["integracoes_oncall"]) or "nenhuma")}</p></div>'
                 f'<div class="card"><h3>Falhas de envio por media type</h3>{table(["Media type", "Falhas"], dict_rows(A_.get("falhas_por_media")))}</div>'
                 f'<div class="card"><h3>Erros de envio mais comuns</h3>{table(["Erro", "Qtde"], A_.get("erros") or [])}</div></div>')
    # 11 · Segurança
    sec_rows = [["Usuários (ativos / com frontend)", f"{SE['usuarios_ativos']} / {SE['usuarios_frontend']}"], ["Super admins", SE["super_admins"]],
                ["Admin padrão ativo", yn(SE["admin_padrao_ativo"])], ["Guest com acesso", yn(SE["guest_ativo"])], ["LDAP", yn(SE["ldap"])], ["SAML", yn(SE["saml"])],
                ["MFA", yn(SE["mfa"])], ["Senha: tamanho mínimo / regras", f"{num(SE['senha_min'])} / {num(SE['senha_regras'])}"],
                ["API tokens ativos (sem expiração / sem uso 90d)", f"{num(SE['tokens_ativos'])} ({num(SE['tokens_sem_expiracao'])} / {num(SE['tokens_sem_uso_90d'])})"],
                ["Grupos com debug mode", len(SE["grupos_debug"])], ["Scripts globais de risco", len(SE["scripts_risco"])],
                ["Macros com segredo em texto plano (global / host)", f"{len(SE['macros_globais_expostas'])} / {SE['macros_host_expostas']}"],
                ["Audit log / retenção (dias)", f"{yn(SE['audit_log'])} / {num(SE['audit_retencao_d'])}"]]
    sec_html = (f'<div class="grid g2"><div class="card"><h3>Postura</h3>{table(["Item", "Valor"], sec_rows)}</div>'
                f'<div class="card"><h3>Itens sensíveis</h3><p><b>Scripts globais de risco:</b> {esc(", ".join(SE["scripts_risco"][:15]) or "—")}</p>'
                f'<p><b>Macros globais expostas:</b> {esc(", ".join(SE["macros_globais_expostas"][:15]) or "—")}</p>'
                f'<p><b>Grupos com debug:</b> {esc(", ".join(SE["grupos_debug"][:15]) or "—")}</p></div></div>')
    # 12 · Higiene
    opp, dp = HY["oportunidades"], HY.get("de_para") or []
    hy_html = (f'<div class="grid g2"><div class="card"><h3>Oportunidades por categoria</h3>{table(["Categoria", "Qtde"], dict_rows(HY["resumo"]))}</div>'
               f'<div class="card"><h3>Carga de polling · DE/PARA (NVPS)</h3>{table(["Categoria", "Objetos", "DE", "PARA", "Redução", "% da carga"], [[r["categoria"], r["objetos"], num(r["de"], 1), num(r["para"], 1), num(r["reducao"], 1), num(r["pct_carga"], 1) + "%"] for r in dp])}'
               f'<p class="mut">NVPS = 1/intervalo dos itens de polling. Base estimada: {num(HY["nvps_base"], 1)} NVPS.</p></div></div>'
               f'<div class="card" style="margin-top:14px"><h3>Maiores oportunidades (amostra)</h3>{table(["Categoria", "Objeto", "Grupo", "Detalhe"], [[o["categoria"], o["nome"], o["grupo"], o["detalhe"]] for o in opp[:25]])}'
               f'<p class="mut">Lista completa em higiene_otimizacao.csv.</p></div>')
    app_rows = [[k, v] for k, v in M["coleta"].items()]

    return f"""<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Assessment Zabbix · {esc(customer)}</title><style>{CSS}</style></head><body><main>
<h1>Assessment Zabbix · Observabilidade e SRE</h1>
<p class="sub">{esc(customer)} · Ambiente {esc(M['ambiente'])} · Zabbix {esc(PL['versao'])} · {esc(M['url_host'])} · Gerado em {M['gerado_em']} · Janela: {days} dias · Coleta somente leitura</p>

<h2>1. Resumo executivo</h2>
<div class="card hero"><div class="ring" style="--p:{overall};--c:{color(overall)}"><i>{overall}</i></div><div style="flex:1;min-width:280px"><h3 style="margin-top:0">Maturidade · {level(overall)}</h3><p style="margin:0">{summary}</p></div></div>
<div class="grid g4" style="margin-top:14px">{kpi_html}</div>

<h2>2. Maturidade por pilar</h2><div class="card">{bars([(p, pil[p]) for p in PILLARS if p in pil])}
{table(["Pilar", "Score", "Atende", "Lacunas", "Lacunas Alta"], pil_rows, raw=True)}<p class="mut" style="margin-bottom:0">{PNOTE}</p></div>

<h2>3. Maturidade por domínio</h2><div class="card">{dom_by_p}</div>

<h2>4. Lacunas priorizadas e recomendações</h2><div class="card">{table(["Prioridade", "Pilar", "Domínio", "Lacuna", "Impacto no negócio", "Recomendação"], find_rows, raw=True) if fails else '<p>Nenhuma lacuna identificada.</p>'}</div>

<h2>5. Roadmap sugerido</h2><div class="grid">{road}</div>

<h2>6. Pontos fortes</h2><div class="card"><ul>{''.join(f'<li><span class="badge sim">{esc(c.pillar)}</span> <b>{esc(c.title)}</b> — {esc(c.evidence)}</li>' for c in oks) or '<li>—</li>'}</ul></div>

<h2>7. Plataforma (server, HA, capacidade, proxies)</h2>{plat_html}

<h2>8. Cobertura de monitoramento</h2>{cov_html}

<h2>9. Alertas e problemas</h2>{alr_html}

<h2>10. Resposta e notificação</h2>{resp_html}

<h2>11. Segurança e governança</h2>{sec_html}

<h2>12. Higiene e otimização da configuração</h2>{hy_html}

<h2>Apêndice A · Status da coleta</h2><div class="card">{table(["Coletor", "Status"], app_rows)}<p class="mut">"parcial" indica método sem permissão para o usuário da API ou erro de coleta; "n/a" indica recurso inexistente na versão. Os controles dependentes ficam N/A ou subestimados.</p></div>
</main></body></html>"""


# --------------------------------------------------------------------------- #
# Relatórios PDF (executivo e técnico) · reportlab  —  imports lazy: opcionais
# --------------------------------------------------------------------------- #

HEX_OK, HEX_WARN, HEX_BAD, HEX_ACC = "#12805C", "#B54708", "#C01048", "#D40000"
HEX_TX, HEX_MUT, HEX_BD, HEX_BG, HEX_SOFT = "#1B1F24", "#667085", "#E4E7EC", "#F6F7F9", "#C9CED6"
SEV_HEX = {"Alta": HEX_BAD, "Média": HEX_WARN, "Baixa": HEX_MUT}
_PDF_FONT = ["Helvetica", "Helvetica-Bold", False]
_ASCII_MAP = str.maketrans({"→": "->", "↔": "<->", "≥": ">=", "≤": "<=", "✓": "v", "✗": "x", "×": "x"})


def hex_score(sc: int) -> str:
    return HEX_OK if sc >= 75 else HEX_WARN if sc >= 50 else HEX_BAD


def next_level(sc: int) -> tuple[str, int] | None:
    for lim in (40, 65, 85):
        if sc < lim:
            return level(lim), lim
    return None


def _pdf_fonts() -> list:
    """Registra uma fonte TrueType com acentuação (DejaVu/Liberation no Linux, Arial no Windows/macOS)."""
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    if _PDF_FONT[2]:
        return _PDF_FONT
    win = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
    pairs = [(Path(p) / "DejaVuSans.ttf", Path(p) / "DejaVuSans-Bold.ttf") for p in
             ("/usr/share/fonts/dejavu", "/usr/share/fonts/dejavu-sans-fonts", "/usr/share/fonts/truetype/dejavu")]
    pairs += [(win / "arial.ttf", win / "arialbd.ttf"), (win / "segoeui.ttf", win / "segoeuib.ttf"),
              (Path("/System/Library/Fonts/Supplemental/Arial.ttf"), Path("/System/Library/Fonts/Supplemental/Arial Bold.ttf"))]
    pairs += [(Path(p) / "LiberationSans-Regular.ttf", Path(p) / "LiberationSans-Bold.ttf") for p in
              ("/usr/share/fonts/liberation-sans", "/usr/share/fonts/truetype/liberation")]
    for reg, bold in pairs:
        if reg.is_file() and bold.is_file():
            try:
                pdfmetrics.registerFont(TTFont("ZBX", str(reg)))
                pdfmetrics.registerFont(TTFont("ZBX-Bold", str(bold)))
                pdfmetrics.registerFontFamily("ZBX", normal="ZBX", bold="ZBX-Bold", italic="ZBX", boldItalic="ZBX-Bold")
                _PDF_FONT[:] = ["ZBX", "ZBX-Bold", True]
                break
            except Exception:  # noqa: BLE001
                continue
    return _PDF_FONT


def _plain(s: Any) -> str:
    s = str(s)
    return s if _PDF_FONT[2] else s.translate(_ASCII_MAP)


def _xe(s: Any) -> str:
    return _plain(html.escape(str(s), quote=False))


def _pdf_styles(font: str, bold: str) -> dict:
    from reportlab.lib import colors
    from reportlab.lib.styles import ParagraphStyle
    c = colors.HexColor
    base = ParagraphStyle("base", fontName=font, fontSize=9.5, leading=13.5, textColor=c(HEX_TX))
    return {
        "base": base,
        "h2": ParagraphStyle("h2", parent=base, fontName=bold, fontSize=14, leading=18, spaceBefore=12, spaceAfter=8, textColor=c(HEX_ACC)),
        "h3": ParagraphStyle("h3", parent=base, fontName=bold, fontSize=10, leading=13, spaceBefore=8, spaceAfter=4, textColor=c(HEX_MUT)),
        "small": ParagraphStyle("small", parent=base, fontSize=7.5, leading=10, textColor=c(HEX_MUT)),
        "td": ParagraphStyle("td", parent=base, fontSize=7.8, leading=10),
        "th": ParagraphStyle("th", parent=base, fontName=bold, fontSize=7.5, leading=9.5, textColor=colors.white),
        "kpi": ParagraphStyle("kpi", parent=base, fontName=bold, fontSize=14, leading=17),
        "bullet": ParagraphStyle("bullet", parent=base, leftIndent=12, bulletIndent=2, spaceAfter=3),
    }


def _pdf_table(S: dict, headers: list[str], rows: list[list[Any]], width: float, fr: list[float] | None = None) -> Any:
    from reportlab.lib import colors
    from reportlab.platypus import Flowable, Paragraph, Table, TableStyle
    if not rows:
        return Paragraph("Sem dados.", S["small"])
    fr = fr or [1] * len(headers)
    data = [[Paragraph(_xe(h), S["th"]) for h in headers]]
    data += [[v if isinstance(v, (Flowable, list)) else Paragraph(_xe("-" if v is None else v), S["td"]) for v in r] for r in rows]
    t = Table(data, colWidths=[width * f / sum(fr) for f in fr], repeatRows=1, hAlign="LEFT")
    st = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor(HEX_TX)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
          ("LINEBELOW", (0, 1), (-1, -1), 0.4, colors.HexColor(HEX_BD)), ("TOPPADDING", (0, 0), (-1, -1), 3.5),
          ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    st += [("BACKGROUND", (0, i), (-1, i), colors.HexColor(HEX_BG)) for i in range(2, len(data), 2)]
    t.setStyle(TableStyle(st))
    return t


def _pdf_side(blocks: list[list[Any]], width: float) -> Any:
    from reportlab.platypus import Table, TableStyle
    t = Table([blocks], colWidths=[width / len(blocks)] * len(blocks))
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 10)]))
    return t


def _pdf_kpis(S: dict, kpis: list[tuple[str, Any]], width: float, cols: int = 4) -> Any:
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph, Table, TableStyle
    cells = [[Paragraph(_xe(v), S["kpi"]), Paragraph(_xe(k), S["small"])] for k, v in kpis]
    cells += [""] * (-len(cells) % cols)
    t = Table([cells[i:i + cols] for i in range(0, len(cells), cols)], colWidths=[width / cols] * cols)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(HEX_BG)), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("LINEAFTER", (0, 0), (-1, -1), 4, colors.white), ("LINEBELOW", (0, 0), (-1, -1), 4, colors.white),
                           ("LINEBEFORE", (0, 0), (0, -1), 3, colors.HexColor(HEX_ACC)),
                           ("TOPPADDING", (0, 0), (-1, -1), 7), ("BOTTOMPADDING", (0, 0), (-1, -1), 7), ("LEFTPADDING", (0, 0), (-1, -1), 9)]))
    return t


def _pdf_bars(items: list[tuple[str, int]], width: float, label_w: float = 165, row_h: float = 17, invert: bool = False, suffix: str = "") -> Any:
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.lib import colors
    font, bold, _ = _PDF_FONT
    h = row_h * len(items) + 2
    dr = Drawing(width, h)
    bw = width - label_w - 34
    for i, (k, v) in enumerate(items):
        y = h - (i + 1) * row_h + 3
        col = colors.HexColor(hex_score(100 - v if invert else v))
        dr.add(String(0, y + 1.5, _plain(clip(k, 38)), fontName=font, fontSize=8.5, fillColor=colors.HexColor(HEX_TX)))
        dr.add(Rect(label_w, y + 1, bw, 8, rx=4, ry=4, fillColor=colors.HexColor(HEX_BD), strokeColor=None))
        if v:
            dr.add(Rect(label_w, y + 1, max(8, bw * min(v, 100) / 100), 8, rx=4, ry=4, fillColor=col, strokeColor=None))
        dr.add(String(width, y + 1.5, f"{round(v)}{suffix}", fontName=bold, fontSize=9, textAnchor="end", fillColor=col))
    return dr


def _pdf_gauge(sc: int, size: float) -> Any:
    from reportlab.graphics.shapes import Circle, Drawing, String, Wedge
    from reportlab.lib import colors
    font, bold, _ = _PDF_FONT
    dr, c, r = Drawing(size, size), size / 2, size / 2
    col = colors.HexColor(hex_score(sc))
    dr.add(Circle(c, c, r, fillColor=colors.HexColor(HEX_BD), strokeColor=None))
    if sc >= 100:
        dr.add(Circle(c, c, r, fillColor=col, strokeColor=None))
    elif sc > 0:
        dr.add(Wedge(c, c, r, 90 - 3.6 * sc, 90, fillColor=col, strokeColor=None))
    dr.add(Circle(c, c, r * 0.76, fillColor=colors.white, strokeColor=None))
    dr.add(String(c, c - size * 0.06, str(sc), fontName=bold, fontSize=size * 0.30, textAnchor="middle", fillColor=col))
    dr.add(String(c, c - size * 0.22, "/100", fontName=font, fontSize=size * 0.09, textAnchor="middle", fillColor=colors.HexColor(HEX_MUT)))
    return dr


def _pdf_doc(path: Path, d: dict, customer: str, subtitle: str, x: dict, land: bool) -> tuple:
    """Documento A4 com capa (1ª página) e cabeçalho/rodapé nas demais."""
    from reportlab.graphics import renderPDF
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.units import mm
    from reportlab.platypus import Flowable, PageBreak, SimpleDocTemplate
    font, bold, _ = _pdf_fonts()
    S = _pdf_styles(font, bold)
    ps = landscape(A4) if land else A4
    M, hx, PL = d["meta"], colors.HexColor, d["platform"]
    doc = SimpleDocTemplate(str(path), pagesize=ps, leftMargin=16 * mm, rightMargin=16 * mm, topMargin=18 * mm, bottomMargin=16 * mm,
                            title=f"Assessment Zabbix - {subtitle} - {customer}", author="zabbix_assessment.py", subject="Assessment Zabbix")

    def later(cv, dc):
        w, h = ps
        cv.saveState()
        cv.setFillColor(hx(HEX_ACC))
        cv.rect(0, h - 5, w, 5, fill=1, stroke=0)
        cv.setFont(font, 7.5)
        cv.setFillColor(hx(HEX_MUT))
        cv.drawString(dc.leftMargin, h - 11 * mm, _plain(f"Assessment Zabbix · {subtitle} · {customer}"))
        cv.drawRightString(w - dc.rightMargin, h - 11 * mm, "Confidencial")
        cv.drawString(dc.leftMargin, 8 * mm, _plain(f"Ambiente {M['ambiente']} · Zabbix {PL['versao']} · gerado em {M['gerado_em']} · coleta somente leitura"))
        cv.drawRightString(w - dc.rightMargin, 8 * mm, f"Página {dc.page}")
        cv.restoreState()

    def first(cv, dc):
        w, h = ps
        by, L, gs, ov = h * (0.46 if land else 0.57), 22 * mm, 130, x["overall"]
        cv.saveState()
        cv.setFillColor(hx(HEX_TX))
        cv.rect(0, by, w, h - by, fill=1, stroke=0)
        cv.setFillColor(hx(HEX_ACC))
        cv.rect(0, by - 6, w, 6, fill=1, stroke=0)
        cv.setFont(bold, 9.5)
        cv.drawString(L, h - 70, "ZABBIX · OBSERVABILIDADE E SRE")
        cv.setFillColor(colors.white)
        cv.setFont(bold, 30)
        cv.drawString(L, h - 115, "Assessment de monitoramento")
        cv.setFillColor(hx(HEX_SOFT))
        cv.setFont(font, 17)
        cv.drawString(L, h - 142, _plain(subtitle))
        cv.setFillColor(colors.white)
        cv.setFont(bold, 16)
        cv.drawString(L, h - 192, _plain(clip(customer, 70)))
        cv.setFillColor(hx(HEX_SOFT))
        cv.setFont(font, 10)
        for i, ln in enumerate([f"Ambiente {M['ambiente']} · Zabbix {PL['versao']} · {M['url_host']}",
                                f"{x['n_mon']} hosts monitorados · {num(d['items']['habilitados'])} itens · {num(d['triggers']['habilitadas'])} triggers",
                                f"Gerado em {M['gerado_em']} · janela de {M['days']} dias · coleta somente leitura"]):
            cv.drawString(L, h - 214 - i * 15, _plain(clip(ln, 120)))
        gy = by / 2 - gs / 2 + 12
        renderPDF.draw(_pdf_gauge(ov, gs), cv, L, gy)
        tx = L + gs + 32
        cv.setFillColor(hx(HEX_MUT))
        cv.setFont(bold, 9)
        cv.drawString(tx, gy + gs - 8, "MATURIDADE DE OBSERVABILIDADE")
        cv.setFillColor(hx(hex_score(ov)))
        cv.setFont(bold, 20)
        cv.drawString(tx, gy + gs - 34, level(ov))
        bars = _pdf_bars([(p, x["pil"][p]) for p in PILLARS if p in x["pil"]], min(w - tx - L, 340), label_w=150)
        renderPDF.draw(bars, cv, tx, gy + gs - 46 - bars.height)
        cv.setFillColor(hx(HEX_MUT))
        cv.setFont(font, 7.5)
        cv.drawString(L, 12 * mm, "Confidencial · gerado automaticamente por zabbix_assessment.py a partir da API do Zabbix (somente leitura)")
        cv.restoreState()

    class _CoverFill(Flowable):
        def wrap(self, aw, ah):
            return aw, ah - 1

        def draw(self):
            pass

    doc._zbx_pages = (first, later)
    return doc, S, [_CoverFill(), PageBreak()], doc.width


def _pdf_sev(S: dict, sev: str) -> Any:
    from reportlab.platypus import Paragraph
    return Paragraph(f'<font color="{SEV_HEX.get(sev, HEX_MUT)}"><b>{_xe(sev)}</b></font>', S["td"])


def _pdf_score(S: dict, v: int | None) -> Any:
    from reportlab.platypus import Paragraph
    return Paragraph("N/A" if v is None else f'<font color="{hex_score(v)}"><b>{v}</b></font>', S["td"])


def _pdf_cov(S: dict, n: int, t: int) -> Any:
    from reportlab.platypus import Paragraph
    if not t:
        return Paragraph("—", S["td"])
    p = pct(n, t)
    col = HEX_OK if p >= 80 else HEX_WARN if p >= 40 else HEX_BAD
    return Paragraph(f'<font color="{col}"><b>{n}/{t}</b> · {p}%</font>', S["td"])


def _pdf_pillar_rows(S: dict, checks: list[Check], pil: dict[str, int], with_counts: bool) -> list[list[Any]]:
    rows = []
    for p in PILLARS:
        cs = [c for c in checks if c.pillar == p and c.passed is not None]
        if not cs:
            continue
        sc = pil.get(p)
        fs = [c for c in cs if not c.passed]
        base = [p, _pdf_score(S, sc), level(sc) if sc is not None else "—"]
        if with_counts:
            rows.append(base + [sum(1 for c in cs if c.passed), len(fs), sum(1 for c in fs if c.severity == "Alta")])
        else:
            rows.append(base + [sum(1 for c in fs if c.severity == s) for s in SEV_ORDER])
    return rows


def build_pdf_exec(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str, path: Path) -> None:
    from reportlab.platypus import CondPageBreak, KeepTogether, Paragraph, Spacer
    x = report_ctx(d, checks, pil, overall)
    doc, S, story, W = _pdf_doc(path, d, customer, "Relatório executivo", x, land=False)
    EV, HY, PR = d["events"], x["hy"], d["problems"]
    P = lambda m, s="base": Paragraph(m, S[s])  # noqa: E731

    story += [P("1. Resumo executivo", "h2"), P(exec_summary(d, x, e=_xe)), Spacer(1, 10), _pdf_kpis(S, x["kpis"], W),
              KeepTogether([P("Maturidade por pilar", "h3"), _pdf_bars([(p, pil[p]) for p in PILLARS if p in pil], W),
                            Spacer(1, 6), _pdf_table(S, ["Pilar", "Score", "Nível", "Lacunas Alta", "Média", "Baixa"],
                                                     _pdf_pillar_rows(S, checks, pil, False), W, [3, 1, 2, 1.2, 1, 1]),
                            P(PNOTE, "small")])]
    story += [CondPageBreak(140), P("2. Principais riscos para a operação", "h2")]
    top = x["high"] or x["fails"]
    if top:
        story.append(P(f"{len(x['high'])} lacunas de prioridade alta exigem ação nos próximos 30 dias. "
                       + ("Os itens abaixo concentram o maior risco de incidente não detectado, alerta perdido ou exposição de segurança." if x["high"] else
                          "Não há lacunas de prioridade alta; abaixo, as mais relevantes.")))
        story.append(Spacer(1, 6))
        story.append(_pdf_table(S, ["Prioridade", "Pilar", "Risco identificado", "Impacto", "Ação recomendada"],
                                [[_pdf_sev(S, c.severity), c.pillar, P(f"<b>{_xe(c.title)}</b>", "td"), c.impact, c.recommendation] for c in top[:12]],
                                W, [1, 1.4, 1.9, 2.4, 2.6]))
        if len(top) > 12:
            story.append(P(f"+{len(top) - 12} itens no relatório técnico.", "small"))
    else:
        story.append(P("Nenhuma lacuna identificada nos controles avaliados."))

    dp = HY.get("de_para") or []
    story += [CondPageBreak(200), P("3. Alertas, carga e higiene", "h2"),
              _pdf_kpis(S, [(f"Problemas em {d['meta']['days']}d", num(EV["total"])), ("MTTR mediano (min)", num(EV["mttr_mediana_min"], 1)),
                            ("Problemas abertos > 30d", num(PR["mais_30d"])), ("Oportunidades de higiene", num(len(HY["oportunidades"])))], W),
              Spacer(1, 8),
              _pdf_side([[P("Triggers mais ruidosas", "h3"), _pdf_table(S, ["Trigger", "Disparos"], [[clip(t["trigger"], 60), t["disparos"]] for t in EV["top_triggers"][:6]], W / 2 - 10, [3, 1])],
                         [P("Higiene por categoria", "h3"), _pdf_table(S, ["Categoria", "Qtde"], dict_rows(HY["resumo"])[:7], W / 2 - 10, [3, 1])]], W)]
    if dp:
        de, para = sum(r["de"] for r in dp), sum(r["para"] for r in dp)
        story.append(KeepTogether([P("Carga de polling · DE/PARA (NVPS)", "h3"),
                                   _pdf_table(S, ["Categoria", "Objetos", "DE (NVPS)", "PARA (NVPS)", "Redução", "% da carga"],
                                              [[r["categoria"], r["objetos"], num(r["de"], 1), num(r["para"], 1),
                                                P(f'<font color="{HEX_OK}"><b>{_xe(num(r["reducao"], 1))}</b></font>', "td"), num(r["pct_carga"], 1) + "%"] for r in dp]
                                              + [[P("<b>Total</b>", "td"), sum(r["objetos"] for r in dp), num(de, 1), num(para, 1),
                                                  P(f'<font color="{HEX_OK}"><b>{_xe(num(de - para, 1))}</b></font>', "td"), num(pct(de - para, HY["nvps_base"])) + "%"]],
                                              W, [2.4, 0.8, 1, 1, 1, 0.9]),
                                   P("NVPS = valores/s de polling (1/intervalo). Reduzir carga libera pollers, I/O de banco e capacidade para crescer sem novo hardware.", "small")]))

    story += [CondPageBreak(140), P("4. Roadmap sugerido (30 · 60 · 90 dias)", "h2")]
    for sev, label in ROADMAP:
        items = [c for c in x["fails"] if c.severity == sev]
        if items:
            story.append(KeepTogether([P(f"{label} · prioridade {sev} ({len(items)})", "h3")]
                                      + [Paragraph(f"<b>{_xe(c.title)}</b> <font color='{HEX_MUT}'>· {_xe(c.pillar)}</font>", S["bullet"], bulletText="•") for c in items]))
    story += [CondPageBreak(140), P("5. Pontos fortes", "h2")]
    story += [Paragraph(f"<b>{_xe(c.title)}</b> <font color='{HEX_MUT}'>· {_xe(c.pillar)}</font>", S["bullet"], bulletText="✓" if _PDF_FONT[2] else "•")
              for c in x["oks"][:14]] or [P("—")]
    nl = next_level(overall)
    steps = ["Validar os achados com os times de plataforma, operações (NOC/on-call), segurança e donos de serviço.",
             f"Designar responsáveis e datas para as {len(x['high'])} lacunas de prioridade alta (janela de 0 a 30 dias).",
             "Aprovar o roadmap 30/60/90 e o modelo de execução (templates e configuração como código via API/Terraform)."]
    if HY["oportunidades"]:
        steps.append(f"Tratar as {len(HY['oportunidades'])} oportunidades de higiene (detalhe em higiene_otimizacao.csv).")
    steps.append("Reexecutar o assessment em 90 dias para medir a evolução" + (f" (meta: nível {nl[0]}, score ≥ {nl[1]})." if nl else " e manter o nível Otimizado."))
    story.append(KeepTogether([P("6. Próximos passos e decisões", "h2")] + [Paragraph(_xe(s), S["bullet"], bulletText=f"{i}.") for i, s in enumerate(steps, 1)]
                              + [Spacer(1, 8), P("Evidências por controle e inventário: relatorio_tecnico.pdf · backlog: achados.csv.", "small")]))
    first, later = doc._zbx_pages
    doc.build(story, onFirstPage=first, onLaterPages=later)


def build_pdf_tech(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str, path: Path) -> None:
    from reportlab.platypus import CondPageBreak, KeepTogether, PageBreak, Paragraph, Spacer
    x = report_ctx(d, checks, pil, overall)
    doc, S, story, W = _pdf_doc(path, d, customer, "Relatório técnico", x, land=True)
    M, PL, IT, TR, PR, EV, AL, SE, HY, LL = (d["meta"], d["platform"], d["items"], d["triggers"], d["problems"], d["events"], d["alerting"],
                                             d["security"], x["hy"], d["lld"])
    days, H, srv = M["days"], W / 2 - 10, x["srv"]
    P = lambda m, s="base": Paragraph(m, S[s])  # noqa: E731
    T = lambda h, r, w=W, fr=None: _pdf_table(S, h, r, w, fr)  # noqa: E731

    def h2(t):
        story.extend([CondPageBreak(150), P(t, "h2")])

    h2("1. Escopo e metodologia")
    story.append(_pdf_side([[T(["Item", "Valor"], [
        ["Cliente", customer], ["Ambiente", M["ambiente"]], ["Endpoint", M["url_host"]], ["Versão", PL["versao"]],
        ["Hosts (total / monitorados)", f"{len(d['hosts'])} / {x['n_mon']}"], ["Escopo de host groups", M.get("escopo_grupos") or "todos"],
        ["Janela de eventos", f"{days} dias"], ["Autenticação", M.get("auth", "-")], ["Chamadas de API (leitura)", M.get("chamadas_api", "-")],
        ["Duração da coleta", f"{M.get('duracao_s', '-')} s"], ["Gerado em", M["gerado_em"]]], H, [1, 2])],
        [P("<b>Abordagem.</b> Coleta 100% somente leitura via API JSON-RPC: o cliente só permite métodos *.get. Recomenda-se ainda "
           "uma role com allow list '*.get' no próprio Zabbix. Os dados são avaliados contra controles de cinco pilares de maturidade."),
         Spacer(1, 6), P(f"<b>Pontuação.</b> {_xe(PNOTE)} Controles sem dados (N/A) não entram no cálculo. "
                         f"Foram avaliados {len(x['evaluated'])} controles: {len(x['oks'])} atendidos e {len(x['fails'])} lacunas."),
         Spacer(1, 6), P("<b>Níveis.</b> Inicial (&lt;40) · Em desenvolvimento (40–64) · Estruturado (65–84) · Otimizado (≥85)."),
         Spacer(1, 6), P("<b>Limitações.</b> NVPS estimado = soma de 1/intervalo dos itens de polling (exclui trapper/dependente). "
                         "Capacidade do server depende do template de self-monitoring. Coletores 'parcial' (Apêndice A) indicam permissões ausentes.")]], W))
    h2("2. Maturidade por pilar")
    story += [P(exec_summary(d, x, e=_xe)), Spacer(1, 8),
              _pdf_side([[_pdf_bars([(p, pil[p]) for p in PILLARS if p in pil], H)],
                         [T(["Pilar", "Score", "Nível", "Atende", "Lacunas", "Alta"], _pdf_pillar_rows(S, checks, pil, True), H, [3, 1, 2, 1, 1, 1])]], W)]
    h2("3. Maturidade por domínio")
    blocks = []
    for p in PILLARS:
        items = sorted(((k, v) for k, v in dom.items() if any(c.domain == k and c.pillar == p for c in checks)), key=lambda kv: kv[1])
        if items:
            blocks.append([P(p, "h3"), _pdf_bars(items, H)])
    for i in range(0, len(blocks), 2):
        pair = blocks[i:i + 2]
        story.append(_pdf_side(pair + [[]] * (2 - len(pair)), W))
    h2("4. Lacunas priorizadas e recomendações")
    story.append(T(["Prioridade", "Pilar", "Domínio", "Lacuna e evidência", "Impacto", "Recomendação"],
                   [[_pdf_sev(S, c.severity), c.pillar, c.domain, P(f"<b>{_xe(c.title)}</b><br/><font color='{HEX_MUT}'>{_xe(c.evidence)}</font>", "td"),
                     c.impact, c.recommendation] for c in x["fails"]], W, [0.8, 1.2, 1.2, 3.2, 2.2, 2.6]) if x["fails"] else P("Nenhuma lacuna identificada."))
    h2("5. Roadmap sugerido")
    for sev, label in ROADMAP:
        items = [c for c in x["fails"] if c.severity == sev]
        if items:
            story += [P(f"{label} · prioridade {sev} ({len(items)} itens)", "h3"),
                      T(["Pilar", "Domínio", "Ação", "Recomendação"], [[c.pillar, c.domain, P(f"<b>{_xe(c.title)}</b>", "td"), c.recommendation] for c in items], W, [1.2, 1.2, 2.2, 4.5])]
    h2("6. Pontos fortes")
    story.append(T(["Pilar", "Domínio", "Controle atendido", "Evidência"], [[c.pillar, c.domain, P(f"<b>{_xe(c.title)}</b>", "td"), c.evidence] for c in x["oks"]], W, [1.2, 1.2, 2.2, 4.5]))

    h2("7. Plataforma (server, HA, capacidade, proxies)")
    procs = sorted((srv.get("processos") or {}).items(), key=lambda kv: -kv[1])[:16]
    story.append(_pdf_side([[P("Server", "h3"), T(["Item", "Valor"], platform_rows(d, x), H, [1.3, 2])],
                            [P("Ocupação de processos (%)", "h3"), _pdf_bars(procs, H, invert=True, suffix="%") if procs else P("Sem self-monitoring do server.", "small"),
                             P("Caches (% em uso)", "h3"), T(["Cache", "Uso %"], dict_rows(srv.get("caches")), H, [3, 1])]], W))
    hbp = Counter(h["proxy"] for h in d["hosts"] if h["monitored"])
    if PL["proxies"]:
        story += [P("Proxies", "h3"), T(["Proxy", "Modo", "Estado", "Último contato", "Versão", "TLS", "Hosts"],
                                        [[p["name"], p["modo"], "online" if p["online"] else "offline" if p["online"] is False else "N/D",
                                          "-" if p["lastaccess_min"] is None else f"{p['lastaccess_min']} min", p.get("versao") or "-", yn(p["tls"]), hbp.get(p["id"], 0)]
                                         for p in PL["proxies"][:60]], W, [2.5, 1, 1, 1.2, 1, 0.7, 0.8])]

    h2("8. Cobertura de monitoramento")
    cap = [[n, "-" if v is None else num(v), P(f'<font color="{HEX_MUT if v is None else HEX_OK if v > 0 else HEX_BAD}"><b>'
                                              + ("N/D" if v is None else "Em uso" if v > 0 else "Não detectado") + "</b></font>", "td")] for n, v in capability_items(d)]
    half = (len(cap) + 1) // 2
    story.append(_pdf_side([[T(["Capacidade", "Itens", "Situação"], cap[:half], H, [3, 1, 1.3])], [T(["Capacidade", "Itens", "Situação"], cap[half:], H, [3, 1, 1.3])]], W))
    cov = [[g, v["total"], _pdf_cov(S, v.get("disponiveis", 0), v.get("monitorados", 0)), _pdf_cov(S, v.get("com_template", 0), v.get("monitorados", 0)),
            _pdf_cov(S, v.get("com_trigger", 0), v.get("monitorados", 0)), _pdf_cov(S, v.get("sem_nao_suportado", 0), v.get("monitorados", 0)),
            _pdf_cov(S, v.get("com_tag", 0), v.get("monitorados", 0)), _pdf_cov(S, v.get("com_tls", 0), v.get("monitorados", 0))]
           for g, v in list(d["coverage"].items())[:40] if v.get("monitorados")]
    story += [P("Cobertura por host group (top 40)", "h3"),
              T(["Host group", "Hosts", "Disponíveis", "Com template", "Com trigger", "Sem não suportado", "Com tag", "TLS"], cov, W, [2.6, 0.6, 1.1, 1.1, 1.1, 1.1, 1.1, 1.1]),
              _pdf_side([[P("Itens por tipo", "h3"), T(["Tipo", "Itens"], [[k, num(v)] for k, v in dict_rows(IT["por_tipo"])], H, [3, 1])],
                         [P("Erros mais comuns (itens não suportados)", "h3"), T(["Erro", "Itens"], IT["erros"][:12], H, [4, 1]),
                          P(f"LLD: {LL['habilitadas']} regras habilitadas, {LL['nao_suportadas']} não suportadas · Agent 2: {d['agents']['agent2']} hosts.", "small")]], W)]

    h2("9. Alertas e problemas")
    story += [_pdf_kpis(S, [(f"Problemas em {days}d", num(EV["total"])), ("Por dia", num(EV["por_dia"], 1)), ("MTTR mediano (min)", num(EV["mttr_mediana_min"], 1)),
                            ("MTTA mediano (min)", num(EV["mtta_mediana_min"], 1)), ("Problemas abertos", num(PR["abertos"])), ("Abertos > 30 dias", num(PR["mais_30d"])),
                            ("Triggers em flapping", num(EV["flapping_total"])), ("Curta duração (< 5 min)", f"{pct(EV['curta_duracao'], EV['resolvidos'])}%")], W), Spacer(1, 6),
              T(["Severidade", "Triggers habilitadas", "Problemas abertos", f"Problemas em {days}d"],
                [[s, TR["por_severidade"].get(s, 0), PR["por_severidade"].get(s, 0), EV["por_severidade"].get(s, 0)] for s in ZSEV.values()], H, [2, 1, 1, 1]),
              P(f"Triggers que mais dispararam ({days}d)", "h3"),
              T(["Trigger", "Host", "Severidade", "Disparos", "MTTR mediano (min)", "MTTA mediano (min)"],
                [[t["trigger"], t["host"], t["sev"], t["disparos"], num(t["mttr_mediana_min"], 1), num(t["mtta_mediana_min"], 1)] for t in EV["top_triggers"][:20]],
                W, [4, 2, 1, 0.8, 1, 1])]
    if EV["flapping"]:
        story += [P("Triggers em flapping", "h3"), T(["Trigger", "Host", "Disparos", "Duração mediana (min)"],
                                                     [[t["trigger"], t["host"], t["disparos"], num(t["mttr_mediana_min"], 1)] for t in EV["flapping"][:15]], W, [4, 2, 1, 1])]
    story += [P("Problemas abertos mais antigos", "h3"), T(["Problema", "Host", "Severidade", "Dias", "Ack"],
                                                         [[p["nome"], p["host"], p["sev"], p["dias"], yn(p["ack"])] for p in PR["mais_antigos"][:20]], W, [4, 2, 1, 0.6, 0.6])]

    h2("10. Resposta e notificação")
    A_ = AL["alertas"]
    story.append(_pdf_side([[P("Ações e notificação", "h3"), T(["Item", "Valor"], [
        ["Ações de trigger (habilitadas/total)", f"{AL['acoes_trigger_hab']}/{AL['acoes_trigger']}"], ["Com mensagem", AL["acoes_com_mensagem"]],
        ["Com escalonamento", AL["acoes_com_escalonamento"]], ["Com recuperação", AL["acoes_com_recuperacao"]], ["Pausam suprimidos", AL["acoes_pausam_suprimidos"]],
        ["Ações de eventos internos", AL["acoes_internas_hab"]], ["Usuários com media ativa", AL["usuarios_com_media"]],
        [f"Notificações em {days}d / falhas", f"{num(A_.get('total'))} / {num(A_.get('falhas'))}"],
        ["Integrações ITSM/on-call", ", ".join(AL["integracoes_oncall"]) or "nenhuma"]], H, [2, 1.5])],
        [P("Media types em uso", "h3"), T(["Media type", "Usuários"], dict_rows(AL["media_em_uso"])[:10], H, [3, 1]),
         P("Erros de envio mais comuns", "h3"), T(["Erro", "Qtde"], (A_.get("erros") or [])[:8], H, [4, 1])]], W))

    h2("11. Segurança e governança")
    story.append(_pdf_side([[P("Postura", "h3"), T(["Item", "Valor"], [
        ["Usuários ativos / com frontend", f"{SE['usuarios_ativos']} / {SE['usuarios_frontend']}"], ["Super admins", SE["super_admins"]],
        ["Admin padrão ativo", yn(SE["admin_padrao_ativo"])], ["Guest com acesso", yn(SE["guest_ativo"])], ["LDAP / SAML", f"{yn(SE['ldap'])} / {yn(SE['saml'])}"],
        ["MFA", yn(SE["mfa"])], ["API tokens ativos (sem expiração)", f"{num(SE['tokens_ativos'])} ({num(SE['tokens_sem_expiracao'])})"],
        ["Macros com segredo em texto plano (global/host)", f"{len(SE['macros_globais_expostas'])} / {SE['macros_host_expostas']}"],
        ["Scripts globais de risco", len(SE["scripts_risco"])], ["Audit log / retenção", f"{yn(SE['audit_log'])} / {num(SE['audit_retencao_d'])} d"]], H, [2, 1.3])],
        [P("Itens sensíveis", "h3"), P("<b>Scripts de risco:</b> " + _xe(", ".join(SE["scripts_risco"][:12]) or "—"), "td"), Spacer(1, 4),
         P("<b>Macros globais expostas:</b> " + _xe(", ".join(SE["macros_globais_expostas"][:12]) or "—"), "td"), Spacer(1, 4),
         P("<b>Grupos com debug:</b> " + _xe(", ".join(SE["grupos_debug"][:12]) or "—"), "td")]], W))
    acts = score_actions(checks, P_SEC)
    if acts:
        g = lambda a, b: P(f'<font color="{HEX_OK if b > a else HEX_MUT}"><b>{a} → {b}</b>' + (f" (+{b - a})" if b > a else "") + "</font>", "td")  # noqa: E731
        story += [P("Ações para elevar o score de segurança", "h3"),
                  T(["#", "Ação", "Prioridade", "Recomendação", "Score segurança", "Score global", "Global acumulado"],
                    [[i, P(f"<b>{_xe(a['check'].title)}</b>", "td"), _pdf_sev(S, a["check"].severity), a["check"].recommendation,
                      g(a["pilar_de"], a["pilar_para"]), g(a["global_de"], a["global_para"]), _pdf_score(S, a["global_acum"])] for i, a in enumerate(acts, 1)],
                    W, [0.3, 2.4, 0.8, 3.6, 1.1, 1.1, 1]),
                  P("Score se apenas a ação da linha for resolvida; 'Global acumulado' resolve as ações na ordem da tabela.", "small")]

    h2("12. Higiene e otimização da configuração")
    dp, opp = HY.get("de_para") or [], HY["oportunidades"]
    story.append(_pdf_side([[P("Oportunidades por categoria", "h3"), T(["Categoria", "Qtde"], dict_rows(HY["resumo"]), H, [3, 1])],
                            [P("Carga de polling · DE/PARA (NVPS)", "h3"),
                             T(["Categoria", "Objetos", "DE", "PARA", "Redução"], [[r["categoria"], r["objetos"], num(r["de"], 1), num(r["para"], 1), num(r["reducao"], 1)] for r in dp], H, [2.5, 0.8, 0.8, 0.8, 0.8]),
                             P(f"Base estimada: {num(HY['nvps_base'], 1)} NVPS. Ação por categoria em higiene_otimizacao.csv.", "small")]], W))
    story += [P(f"Oportunidades ({min(len(opp), 50)} de {len(opp)}; lista completa em higiene_otimizacao.csv)", "h3"),
              T(["Categoria", "Tipo", "Objeto", "Grupo", "Detalhe", "NVPS DE→PARA"],
                [[o["categoria"], o["tipo"], o["nome"], o["grupo"], o["detalhe"], "-" if o["nvps_de"] is None else f"{num(o['nvps_de'], 2)} → {num(o['nvps_para'], 2)}"] for o in opp[:50]],
                W, [1.6, 0.8, 2.2, 1.6, 2.6, 1.1])]

    st = list(M["coleta"].items())
    half = (len(st) + 1) // 2
    story += [PageBreak() if len(st) > 30 else CondPageBreak(150),
              KeepTogether([P("Apêndice A · Status da coleta", "h2"),
                            _pdf_side([[T(["Coletor", "Status"], [[k, v] for k, v in st[:half]], H, [1, 2])],
                                       [T(["Coletor", "Status"], [[k, v] for k, v in st[half:]], H, [1, 2])]], W),
                            P("'parcial' indica método sem permissão ou erro de coleta; 'n/a' indica recurso inexistente na versão.", "small")])]
    first, later = doc._zbx_pages
    doc.build(story, onFirstPage=first, onLaterPages=later)


# --------------------------------------------------------------------------- #
# Apresentação PowerPoint para stakeholders · python-pptx (16:9, gráficos nativos editáveis)
# --------------------------------------------------------------------------- #


def build_pptx(d: dict, checks: list[Check], dom: dict[str, int], pil: dict[str, int], overall: int, customer: str, path: Path) -> None:
    from pptx import Presentation
    from pptx.chart.data import CategoryChartData
    from pptx.dml.color import RGBColor
    from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION, XL_LEGEND_POSITION, XL_TICK_MARK
    from pptx.enum.shapes import MSO_SHAPE
    from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
    from pptx.oxml.ns import qn
    from pptx.util import Inches, Pt

    x = report_ctx(d, checks, pil, overall)
    M, PL, IT, EV, PR, SE, HY, srv = d["meta"], d["platform"], d["items"], d["events"], d["problems"], d["security"], x["hy"], x["srv"]
    W, FONT = 13.333, "Calibri"
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(W), Inches(7.5)
    blank = prs.slide_layouts[6]
    rgb = lambda h: RGBColor.from_string(h.lstrip("#"))  # noqa: E731
    state = {"n": 0}

    def text(sl, l, t, w, h, paras, size=14, bold=False, color=HEX_TX, align=PP_ALIGN.LEFT, anchor=MSO_ANCHOR.TOP, space=0):
        tb = sl.shapes.add_textbox(Inches(l), Inches(t), Inches(w), Inches(h))
        tf = tb.text_frame
        tf.word_wrap, tf.vertical_anchor = True, anchor
        tf.margin_left = tf.margin_right = Inches(0.04)
        tf.margin_top = tf.margin_bottom = Inches(0.02)
        for i, para in enumerate(paras if isinstance(paras, list) else [paras]):
            p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
            p.alignment = align
            if space:
                p.space_after = Pt(space)
            for seg in (para if isinstance(para, list) else [(para, size, bold, color)]):
                r = p.add_run()
                r.text = str(seg[0])
                f = r.font
                f.name, f.size, f.bold = FONT, Pt(seg[1]), seg[2]
                f.color.rgb = rgb(seg[3])
        return tb

    def box(sl, l, t, w, h, fill, line=None, rounded=False):
        s = sl.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE if rounded else MSO_SHAPE.RECTANGLE, Inches(l), Inches(t), Inches(w), Inches(h))
        if rounded:
            s.adjustments[0] = 0.06
        s.fill.solid()
        s.fill.fore_color.rgb = rgb(fill)
        if line:
            s.line.color.rgb, s.line.width = rgb(line), Pt(0.75)
        else:
            s.line.fill.background()
        s.shadow.inherit = False
        return s

    def slide(title, kicker="", notes=""):
        sl = prs.slides.add_slide(blank)
        state["n"] += 1
        box(sl, 0, 0, W, 0.08, HEX_ACC)
        if kicker:
            text(sl, 0.6, 0.32, 11, 0.3, kicker.upper(), 11, True, HEX_ACC)
        text(sl, 0.6, 0.58, 12.1, 0.7, title, 28, True)
        text(sl, 0.6, 7.02, 9, 0.3, f"{customer} · Assessment Zabbix · Confidencial", 9, color=HEX_MUT)
        text(sl, W - 1.6, 7.02, 1.0, 0.3, str(state["n"]), 9, color=HEX_MUT, align=PP_ALIGN.RIGHT)
        if notes:
            sl.notes_slide.notes_text_frame.text = notes
        return sl

    def tile(sl, l, t, w, h, value, label, accent=HEX_ACC, vsize=26):
        box(sl, l, t, w, h, HEX_BG, rounded=True)
        box(sl, l, t + 0.12, 0.06, h - 0.24, accent)
        text(sl, l + 0.2, t + 0.12, w - 0.3, h * 0.55, str(value), vsize, True, accent if accent != HEX_ACC else HEX_TX, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, l + 0.2, t + h * 0.6, w - 0.3, h * 0.38, label, 11, color=HEX_MUT)

    def style_chart(ch, legend=False):
        ch.font.name, ch.font.size = FONT, Pt(12)
        ch.font.color.rgb = rgb(HEX_TX)
        ch.has_title = False
        ch.has_legend = legend
        if legend:
            ch.legend.position, ch.legend.include_in_layout = XL_LEGEND_POSITION.BOTTOM, False

    def bar_chart(sl, l, t, w, h, cats, series, colors_=None, maxv=None, fmt="0", stacked=False, label_size=12):
        cd = CategoryChartData()
        cd.categories = cats
        for name, vals in series:
            cd.add_series(name, vals)
        ch = sl.shapes.add_chart(XL_CHART_TYPE.BAR_STACKED if stacked else XL_CHART_TYPE.BAR_CLUSTERED, Inches(l), Inches(t), Inches(w), Inches(h), cd).chart
        style_chart(ch, legend=stacked)
        plot = ch.plots[0]
        plot.gap_width = 55
        if stacked:
            plot.overlap = 100
        plot.has_data_labels = True
        dl = plot.data_labels
        dl.font.size, dl.font.bold = Pt(12), True
        dl.number_format, dl.number_format_is_linked = fmt, False
        if not stacked:
            dl.position = XL_LABEL_POSITION.OUTSIDE_END
        va = ch.value_axis
        va.minimum_scale = 0
        if maxv:
            va.maximum_scale = maxv
        va.has_major_gridlines, va.visible = False, False
        ca = ch.category_axis
        ca.reverse_order = True
        ca.major_tick_mark = XL_TICK_MARK.NONE
        ca.format.line.color.rgb = rgb(HEX_BD)
        ca.tick_labels.font.size = Pt(label_size)
        if stacked:
            for s, c in zip(plot.series, colors_ or []):
                s.format.fill.solid()
                s.format.fill.fore_color.rgb = rgb(c)
        else:
            for i, c in enumerate(colors_ or []):
                pt = plot.series[0].points[i]
                pt.format.fill.solid()
                pt.format.fill.fore_color.rgb = rgb(c)
        return ch

    def table(sl, l, t, w, h, headers, rows, widths, size=11, aligns=None, total_row=False):
        tb = sl.shapes.add_table(len(rows) + 1, len(headers), Inches(l), Inches(t), Inches(w), Inches(h)).table
        aligns = aligns or [PP_ALIGN.LEFT] * len(headers)
        for j, wd in enumerate(widths):
            tb.columns[j].width = Inches(w * wd / sum(widths))
        for i in range(len(rows) + 1):
            tb.rows[i].height = Inches(h / (len(rows) + 1))
        for i, r in enumerate([[(hd, "#FFFFFF", True) for hd in headers]] + rows):
            last = total_row and i == len(rows)
            for j, v in enumerate(r):
                c = tb.cell(i, j)
                c.fill.solid()
                c.fill.fore_color.rgb = rgb(HEX_TX if i == 0 else HEX_SOFT if last else HEX_BG if i % 2 == 0 else "#FFFFFF")
                c.margin_left = c.margin_right = Inches(0.07)
                c.margin_top = c.margin_bottom = Inches(0.03)
                c.vertical_anchor = MSO_ANCHOR.MIDDLE
                c.text_frame.word_wrap = True
                paras = v if isinstance(v, list) else [(v[0], size, v[2], v[1]) if isinstance(v, tuple) else (v, size, last, HEX_TX)]
                for k, (txt, sz, b, col) in enumerate(paras):
                    p = c.text_frame.paragraphs[0] if k == 0 else c.text_frame.add_paragraph()
                    p.alignment = aligns[j]
                    run = p.add_run()
                    run.text = str(txt)
                    run.font.name, run.font.size, run.font.bold = FONT, Pt(sz if i else size - 1), b
                    run.font.color.rgb = rgb(col)
        return tb

    def doughnut(sl, l, t, size, sc):
        cd = CategoryChartData()
        cd.categories = ["Score", ""]
        cd.add_series("Score", (sc, 100 - sc))
        ch = sl.shapes.add_chart(XL_CHART_TYPE.DOUGHNUT, Inches(l), Inches(t), Inches(size), Inches(size), cd).chart
        style_chart(ch)
        plot = ch.plots[0]
        plot.has_data_labels = False
        for i, c in enumerate((hex_score(sc), HEX_BD)):
            pt = plot.series[0].points[i]
            pt.format.fill.solid()
            pt.format.fill.fore_color.rgb = rgb(c)
            pt.format.line.fill.background()
        hs = plot._element.find(qn("c:holeSize"))
        if hs is not None:
            hs.set("val", "72")
        text(sl, l, t + size * 0.30, size, size * 0.28, str(sc), 54, True, hex_score(sc), align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, l, t + size * 0.58, size, size * 0.12, "/100", 14, color=HEX_MUT, align=PP_ALIGN.CENTER)

    pils = [p for p in PILLARS if p in pil]
    plain_summary = exec_summary(d, x, b=str, e=str)

    # 1 · Capa
    sl = prs.slides.add_slide(blank)
    state["n"] += 1
    box(sl, 0, 0, W, 7.5, HEX_TX)
    box(sl, 0.8, 2.15, 1.4, 0.08, HEX_ACC)
    text(sl, 0.8, 1.6, 11, 0.4, "ZABBIX · OBSERVABILIDADE E SRE", 14, True, HEX_ACC)
    text(sl, 0.8, 2.45, 11.5, 1.2, "Assessment de monitoramento", 44, True, "#FFFFFF")
    text(sl, 0.8, 3.65, 11.5, 0.6, customer, 26, False, "#FFFFFF")
    text(sl, 0.8, 4.35, 11.5, 0.9, [f"Ambiente {M['ambiente']} · Zabbix {PL['versao']} · {x['n_mon']} hosts monitorados",
                                    f"Gerado em {M['gerado_em']} · coleta somente leitura"], 14, color=HEX_SOFT, space=4)
    text(sl, 0.8, 6.6, 11.5, 0.4, "Apresentação para stakeholders · Confidencial", 12, color=HEX_MUT)
    sl.notes_slide.notes_text_frame.text = (f"Objetivo: apresentar a maturidade do monitoramento Zabbix do ambiente {M['ambiente']}, os principais riscos "
                                            "e o plano de ação proposto, e obter as decisões necessárias.")

    # 2 · Escopo
    sl = slide("Escopo e abordagem", "Contexto", "A coleta usou apenas métodos de leitura da API; nada foi alterado. Cada controle tem peso por criticidade.")
    text(sl, 0.6, 1.55, 6.6, 5.2, [
        [("Ambiente  ", 16, True, HEX_TX), (f"{M['ambiente']} · Zabbix {PL['versao']}", 16, False, HEX_TX)],
        [("Escala  ", 16, True, HEX_TX), (f"{x['n_mon']} hosts · {num(IT['habilitados'])} itens · {num(d['triggers']['habilitadas'])} triggers", 16, False, HEX_TX)],
        [("Proxies  ", 16, True, HEX_TX), (f"{len(PL['proxies'])}", 16, False, HEX_TX)],
        [("Janela  ", 16, True, HEX_TX), (f"{M['days']} dias de eventos e notificações", 16, False, HEX_TX)],
        [("Coleta  ", 16, True, HEX_TX), (f"100% somente leitura via API ({M.get('chamadas_api', '-')} chamadas)", 16, False, HEX_TX)],
        [("Método  ", 16, True, HEX_TX), (f"{len(x['evaluated'])} controles em 5 pilares, ponderados por criticidade", 16, False, HEX_TX)],
    ], space=14)
    for i, p in enumerate(PILLARS):
        n = sum(1 for c in x["evaluated"] if c.pillar == p)
        y = 1.55 + i * 1.0
        box(sl, 7.7, y, 5.0, 0.82, HEX_BG, rounded=True)
        box(sl, 7.7, y + 0.12, 0.06, 0.58, HEX_ACC)
        text(sl, 7.95, y + 0.08, 3.6, 0.66, p, 16, True, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, 11.3, y + 0.08, 1.25, 0.66, f"{n} controles", 12, color=HEX_MUT, align=PP_ALIGN.RIGHT, anchor=MSO_ANCHOR.MIDDLE)

    # 3 · Resultado geral
    sl = slide("Resultado geral", "Resumo executivo", plain_summary)
    doughnut(sl, 0.6, 1.5, 3.9, overall)
    text(sl, 0.6, 5.45, 3.9, 0.5, level(overall), 22, True, hex_score(overall), align=PP_ALIGN.CENTER)
    text(sl, 0.6, 5.95, 3.9, 0.4, "Maturidade de observabilidade", 12, color=HEX_MUT, align=PP_ALIGN.CENTER)
    text(sl, 5.0, 1.55, 7.7, 3.2, clip(plain_summary, 760), 14, space=6)
    hosts_av = pct(x["avail"], x["n_mon"])
    for i, (k, v, c) in enumerate([("Hosts monitorados", num(x["n_mon"]), HEX_ACC), ("Hosts disponíveis", f"{hosts_av}%", hex_score(hosts_av)),
                                    ("Lacunas identificadas", len(x["fails"]), HEX_ACC), ("Prioridade alta", len(x["high"]), HEX_BAD if x["high"] else HEX_OK)]):
        tile(sl, 5.0 + i * 1.97, 5.0, 1.82, 1.45, v, k, c, 24)

    # 4 · Pilares
    worst = x["worst"][0] if x["worst"] else None
    sl = slide("Maturidade por pilar", "Observabilidade e SRE", "Score de 0 a 100 por pilar. " + " · ".join(f"{p}: {pil[p]}" for p in pils))
    if pils:
        bar_chart(sl, 0.4, 1.45, 8.4, 5.3, pils, [("Score", [pil[p] for p in pils])], [hex_score(pil[p]) for p in pils], maxv=110)
    if x["best"]:
        tile(sl, 9.2, 1.6, 3.5, 1.5, f"{x['best'][1]}", f"Pilar mais forte · {x['best'][0]}", hex_score(x["best"][1]), 30)
    if worst:
        tile(sl, 9.2, 3.3, 3.5, 1.5, f"{worst[1]}", f"Pilar mais frágil · {worst[0]}", hex_score(worst[1]), 30)
    text(sl, 9.2, 5.05, 3.5, 1.7, ["Níveis de maturidade", "Inicial < 40", "Em desenvolvimento 40–64", "Estruturado 65–84", "Otimizado ≥ 85"], 12, color=HEX_MUT, space=2)

    # 5 · Lacunas
    sl = slide("Onde estão as lacunas", "Lacunas por pilar e prioridade",
               f"{len(x['fails'])} lacunas: " + ", ".join(f"{sum(1 for c in x['fails'] if c.severity == s)} {s.lower()}" for s in SEV_ORDER) + ".")
    gp = [p for p in PILLARS if any(c.pillar == p for c in x["evaluated"])]
    if gp:
        bar_chart(sl, 0.4, 1.45, 8.6, 5.4, gp, [(s, [sum(1 for c in x["fails"] if c.pillar == p and c.severity == s) for p in gp]) for s in SEV_ORDER],
                  [SEV_HEX[s] for s in SEV_ORDER], fmt="0;;;", stacked=True)
    tile(sl, 9.4, 1.6, 3.3, 1.5, len(x["fails"]), "Lacunas identificadas", HEX_ACC, 32)
    for i, s in enumerate(SEV_ORDER):
        tile(sl, 9.4, 3.3 + i * 1.18, 3.3, 1.05, sum(1 for c in x["fails"] if c.severity == s), f"Prioridade {s.lower()}", SEV_HEX[s], 20)

    # 6 · Riscos
    top = x["high"] or x["fails"]
    sl = slide("Principais riscos para a operação", f"{len(x['high'])} lacunas de prioridade alta",
               "\n".join(f"- {c.title}: {c.impact} Recomendação: {c.recommendation}" for c in top[:6]))
    for i, c in enumerate(top[:6]):
        l, t = 0.6 + (i % 2) * 6.15, 1.45 + (i // 2) * 1.74
        box(sl, l, t, 5.95, 1.62, HEX_BG, rounded=True)
        box(sl, l, t + 0.15, 0.06, 1.32, SEV_HEX[c.severity])
        text(sl, l + 0.22, t + 0.08, 5.6, 1.5, [[(c.pillar.upper(), 10, True, SEV_HEX[c.severity])], [(clip(c.title, 75), 15, True, HEX_TX)],
                                                 [(clip(c.impact, 130), 11, False, HEX_MUT)],
                                                 [("Ação: ", 11, True, HEX_TX), (clip(c.recommendation, 150), 11, False, HEX_TX)]], space=2)
    if len(top) > 6:
        text(sl, 0.6, 6.68, 12, 0.3, f"+{len(top) - 6} itens no relatório técnico e no backlog (achados.csv).", 11, color=HEX_MUT)
    if not top:
        text(sl, 0.6, 1.6, 12, 1, "Nenhuma lacuna identificada nos controles avaliados.", 18)

    # 7 · Plataforma
    sp = PL["suporte"]
    sl = slide("Saúde da plataforma", P_PLAT, f"Zabbix {PL['versao']} (suporte {sp['status']}). NVPS {num(x['nvps'], 1)}. Fila > 10 min: {num(srv.get('queue_10m'))}.")
    off = sum(1 for p in PL["proxies"] if p["online"] is False)
    nodes = PL.get("ha_nodes")
    tiles_ = [(PL["versao"], f"Versão · suporte {sp['status']}", HEX_BAD if sp["status"] == "EOL" else HEX_WARN if sp["status"] == "limitado" else HEX_OK),
              (num(x["nvps"], 1), "NVPS" + ("" if x["nvps_real"] else " (estimado)"), HEX_ACC),
              (num(srv.get("queue_10m")), "Itens atrasados > 10 min", HEX_MUT if srv.get("queue_10m") is None else HEX_OK if srv["queue_10m"] <= 50 else HEX_BAD),
              ("N/D" if nodes is None else len(nodes), "Nós HA do server", HEX_OK if nodes and len(nodes) >= 2 else HEX_WARN),
              (f"{len(PL['proxies']) - off}/{len(PL['proxies'])}", "Proxies online", HEX_BAD if off else HEX_OK)]
    for i, (v, k, c) in enumerate(tiles_):
        tile(sl, 0.6, 1.4 + i * 1.08, 3.6, 0.98, v, k, c, 20)
    procs = sorted((srv.get("processos") or {}).items(), key=lambda kv: -kv[1])[:10]
    if procs:
        text(sl, 4.6, 1.4, 8, 0.35, "Ocupação dos processos do server (%)", 13, True, HEX_MUT)
        bar_chart(sl, 4.5, 1.75, 8.3, 5.0, [k for k, _ in procs], [("Ocupação", [round(v, 1) for _, v in procs])],
                  [hex_score(100 - v) for _, v in procs], maxv=110, fmt="0", label_size=11)
    else:
        text(sl, 4.6, 1.6, 8, 1.2, "Self-monitoring do server não encontrado: vincule o template 'Zabbix server health' ao host do server para medir filas, processos e caches.", 16, color=HEX_MUT)

    # 8 · Alertas
    tt = EV["top_triggers"][:8]
    sl = slide("Qualidade de alertas", P_ALR, f"{num(EV['total'])} problemas em {M['days']} dias ({num(EV['por_dia'], 1)}/dia). "
               + "; ".join(f"{t['trigger']}: {t['disparos']}" for t in tt))
    tiles_ = [(num(EV["por_dia"], 1), f"Problemas por dia ({M['days']}d)", HEX_ACC), (num(EV["mttr_mediana_min"], 1), "MTTR mediano (min)", HEX_ACC),
              (num(EV["mtta_mediana_min"], 1), "MTTA mediano (min)", HEX_ACC), (num(EV["flapping_total"]), "Triggers em flapping", HEX_BAD if EV["flapping_total"] else HEX_OK),
              (num(PR["mais_30d"]), "Problemas abertos > 30 dias", HEX_BAD if PR["mais_30d"] else HEX_OK)]
    for i, (v, k, c) in enumerate(tiles_):
        tile(sl, 0.6, 1.4 + i * 1.08, 3.6, 0.98, v, k, c, 20)
    if tt:
        text(sl, 4.6, 1.4, 8, 0.35, "Triggers que mais dispararam", 13, True, HEX_MUT)
        bar_chart(sl, 4.5, 1.75, 8.3, 5.0, [clip(t["trigger"], 48) for t in tt], [("Disparos", [t["disparos"] for t in tt])], [HEX_ACC] * len(tt), label_size=10)

    # 9 · Higiene
    dp = HY.get("de_para") or []
    if HY["oportunidades"]:
        de, para = sum(r["de"] for r in dp), sum(r["para"] for r in dp)
        sl = slide("Higiene e carga de coleta", "Oportunidades de otimização",
                   f"{len(HY['oportunidades'])} oportunidades. Redução estimada de {num(de - para, 1)} NVPS ({pct(de - para, HY['nvps_base'])}% da carga de polling).")
        for i, (v, k, c) in enumerate([(num(len(HY["oportunidades"])), "Oportunidades mapeadas", HEX_TX), (num(de, 1), "DE · NVPS das categorias", HEX_TX),
                                       (num(para, 1), "PARA · NVPS após ações", HEX_ACC), (f"{pct(de - para, HY['nvps_base'])}%", "Carga de polling liberada", HEX_OK)]):
            tile(sl, 0.6 + i * 3.06, 1.4, 2.9, 1.15, v, k, c, 22)
        R = PP_ALIGN.RIGHT
        res = dict_rows(HY["resumo"])
        dpm = {r["categoria"]: r for r in dp}
        rows = [[[(cat, 11, True, HEX_TX), (NVPS_RULES.get(cat, (0, ""))[1], 9, False, HEX_MUT)], f"{n}",
                 num(dpm[cat]["de"], 1) if cat in dpm else "—", num(dpm[cat]["para"], 1) if cat in dpm else "—",
                 (num(dpm[cat]["reducao"], 1), HEX_OK, True) if cat in dpm else "—"] for cat, n in res[:8]]
        table(sl, 0.6, 2.75, 12.1, min(3.75, 0.45 * (len(rows) + 1)), ["Categoria · ação", "Objetos", "NVPS DE", "NVPS PARA", "Redução"],
              rows, [6.2, 1.2, 1.5, 1.5, 1.5], 11, [PP_ALIGN.LEFT, R, R, R, R])
        text(sl, 0.6, 6.55, 12.1, 0.4, "NVPS = valores/s de polling (1/intervalo). Lista por objeto em higiene_otimizacao.csv.", 9, color=HEX_MUT)

    # 10 · Segurança
    acts = score_actions(checks, P_SEC)
    pil_sec = pil.get(P_SEC)
    sl = slide("Segurança e governança", P_SEC, "Ações ordenadas pelo ganho no score global: " + "; ".join(
        f"{a['check'].title}: segurança {a['pilar_de']}→{a['pilar_para']}, global {a['global_de']}→{a['global_para']}" for a in acts) if acts else "Sem lacunas no pilar.")
    if pil_sec is not None:
        text(sl, 9.0, 0.62, 3.7, 0.6, f"Score do pilar: {pil_sec}", 18, True, hex_score(pil_sec), align=PP_ALIGN.RIGHT)
    ext = None if SE["ldap"] is None else bool(SE["ldap"] or SE["saml"])
    sec_t = [(f"{SE['super_admins']}", "Super admins", HEX_WARN if SE["super_admins"] > 5 else HEX_OK),
             ("N/D" if ext is None else "sim" if ext else "não", "LDAP/SAML", HEX_MUT if ext is None else HEX_OK if ext else HEX_BAD),
             (num(SE["tokens_sem_expiracao"]), "Tokens sem expiração", HEX_MUT if SE["tokens_sem_expiracao"] is None else HEX_BAD if SE["tokens_sem_expiracao"] else HEX_OK),
             (f"{len(SE['macros_globais_expostas']) + SE['macros_host_expostas']}", "Macros com segredo exposto", HEX_BAD if SE["macros_globais_expostas"] or SE["macros_host_expostas"] else HEX_OK),
             (len(SE["scripts_risco"]), "Scripts globais de risco", HEX_WARN if SE["scripts_risco"] else HEX_OK),
             (yn(SE["audit_log"]), "Audit log", HEX_MUT if SE["audit_log"] is None else HEX_OK if SE["audit_log"] else HEX_BAD)]
    for i, (v, k, c) in enumerate(sec_t):
        tile(sl, 0.6 + i * 2.03, 1.4, 1.93, 1.0, v, k, c, 18)
    if acts:
        def gain(a, b):
            return (f"{a} → {b}" + (f"  (+{b - a})" if b > a else ""), HEX_OK if b > a else HEX_MUT, b > a)
        shown = acts[:5]
        rows = [[f"{i}", [(clip(a["check"].title, 70), 12, True, HEX_TX), (clip(a["check"].recommendation, 115), 10, False, HEX_MUT)],
                 (a["check"].severity, SEV_HEX[a["check"].severity], True), gain(a["pilar_de"], a["pilar_para"]), gain(a["global_de"], a["global_para"]),
                 (f"{a['global_acum']}", hex_score(a["global_acum"]), True)] for i, a in enumerate(shown, 1)]
        C_ = PP_ALIGN.CENTER
        text(sl, 0.6, 2.55, 12, 0.35, "Ações para elevar o score (ganho se apenas esta ação for resolvida)", 13, True, HEX_MUT)
        table(sl, 0.6, 2.92, 12.1, min(3.45, 0.62 * (len(rows) + 1)), ["#", "Ação recomendada", "Prioridade", "Score segurança", "Score global", "Global acumulado"],
              rows, [0.35, 6.1, 1.1, 1.55, 1.55, 1.45], 11, [C_, PP_ALIGN.LEFT, C_, C_, C_, C_])
        last = acts[-1]
        text(sl, 0.6, 6.45, 12.1, 0.45, [[("Resolvendo as " + str(len(acts)) + " lacunas de segurança: ", 12, True, HEX_TX),
                                          (f"pilar {acts[0]['pilar_de']} → {last['pilar_acum']} · score global {acts[0]['global_de']} → {last['global_acum']}", 12, True, HEX_OK)]])
    else:
        text(sl, 0.6, 2.7, 12, 0.6, "Nenhuma lacuna no pilar de segurança nos controles avaliados.", 16)

    # 11 · Roadmap
    sl = slide("Roadmap sugerido", "Plano 30 · 60 · 90 dias",
               " | ".join(f"{label}: {sum(1 for c in x['fails'] if c.severity == s)} itens de prioridade {s.lower()}" for s, label in ROADMAP))
    for i, (sev, label) in enumerate(ROADMAP):
        items = [c for c in x["fails"] if c.severity == sev]
        l = 0.6 + i * 4.1
        box(sl, l, 1.5, 3.9, 0.75, SEV_HEX[sev], rounded=True)
        text(sl, l + 0.15, 1.53, 3.6, 0.7, [[(label, 18, True, "#FFFFFF")], [(f"Prioridade {sev.lower()} · {len(items)} itens", 11, False, "#FFFFFF")]], anchor=MSO_ANCHOR.MIDDLE)
        box(sl, l, 2.35, 3.9, 4.45, HEX_BG, rounded=True)
        lines = [[("•  ", 12, True, SEV_HEX[sev]), (clip(c.title, 52), 12, False, HEX_TX)] for c in items[:11]]
        if len(items) > 11:
            lines.append([(f"+{len(items) - 11} itens no relatório técnico", 11, True, HEX_MUT)])
        text(sl, l + 0.15, 2.5, 3.6, 4.2, lines or "Nenhum item.", 12, color=HEX_MUT, space=5)

    # 12 · Pontos fortes
    sl = slide("Pontos fortes", f"{len(x['oks'])} controles atendidos", "\n".join(f"- {c.title}: {c.evidence}" for c in x["oks"][:12]))
    oks = x["oks"][:12]
    for i, c in enumerate(oks):
        l, t = 0.6 + (i // 6) * 6.15, 1.5 + (i % 6) * 0.86
        text(sl, l, t, 0.4, 0.4, "✓", 18, True, HEX_OK)
        text(sl, l + 0.42, t, 5.5, 0.8, [[(clip(c.title, 62), 15, True, HEX_TX)], [(f"{c.pillar} · {clip(c.evidence, 70)}", 11, False, HEX_MUT)]])
    if len(x["oks"]) > 12:
        text(sl, 0.6, 6.68, 12, 0.3, f"+{len(x['oks']) - 12} controles atendidos no relatório técnico.", 11, color=HEX_MUT)
    if not oks:
        text(sl, 0.6, 1.6, 12, 1, "Nenhum controle atendido integralmente.", 18)

    # 13 · Próximos passos
    nl = next_level(overall)
    steps = [("Validar achados", "Confirmar evidências e priorização com plataforma, NOC/on-call, segurança e donos de serviço."),
             ("Designar responsáveis", f"Owners e datas para as {len(x['high'])} lacunas de prioridade alta (0–30 dias)."),
             ("Aprovar o roadmap", "Patrocínio e capacidade para o plano 30/60/90 (configuração como código via API).")]
    if HY["oportunidades"]:
        steps.append(("Higienizar a configuração", f"Tratar as {len(HY['oportunidades'])} oportunidades mapeadas (itens, hosts, templates)."))
    steps.append(("Medir a evolução", "Reexecutar o assessment em 90 dias" + (f" · meta: {nl[0]} (score ≥ {nl[1]})." if nl else " · manter o nível Otimizado.")))
    sl = slide("Próximos passos e decisões", "Encaminhamentos", "Decisões solicitadas: aprovação do roadmap, responsáveis e cadência de acompanhamento.")
    for i, (h, t_) in enumerate(steps):
        y = 1.5 + i * 1.05
        box(sl, 0.6, y, 0.75, 0.75, HEX_ACC, rounded=True)
        text(sl, 0.6, y, 0.75, 0.75, str(i + 1), 22, True, "#FFFFFF", align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
        text(sl, 1.6, y - 0.02, 6.6, 0.85, [[(h, 17, True, HEX_TX)], [(t_, 13, False, HEX_MUT)]], anchor=MSO_ANCHOR.MIDDLE)
    box(sl, 8.7, 1.5, 4.0, 4.95, HEX_TX, rounded=True)
    text(sl, 8.95, 1.7, 3.5, 4.6, [[("Decisões solicitadas", 18, True, "#FFFFFF")], [("", 8, False, HEX_SOFT)],
                                   [("•  Aprovar o roadmap 30/60/90", 14, False, HEX_SOFT)], [("•  Nomear responsáveis por pilar", 14, False, HEX_SOFT)],
                                   [("•  Definir cadência de acompanhamento (quinzenal)", 14, False, HEX_SOFT)],
                                   [("•  Agendar reavaliação em 90 dias", 14, False, HEX_SOFT)]], space=8)
    prs.core_properties.title = f"Assessment Zabbix - {customer}"
    prs.core_properties.author = "zabbix_assessment.py"
    prs.save(str(path))


# --------------------------------------------------------------------------- #
# Saídas
# --------------------------------------------------------------------------- #

EXTRA_OUTPUTS = {"pdf": [("relatorio_executivo.pdf", build_pdf_exec), ("relatorio_tecnico.pdf", build_pdf_tech)],
                 "pptx": [("apresentacao_stakeholders.pptx", build_pptx)]}


def render_extras(d: dict, checks: list[Check], dom: dict, pil: dict, overall: int, out: Path, customer: str, formats: list[str]) -> None:
    for fmt in formats:
        for name, fn in EXTRA_OUTPUTS.get(fmt, []):
            try:
                fn(d, checks, dom, pil, overall, customer, out / name)
                log(f"gerado {name}")
            except ImportError as e:
                log(f"{name} não gerado: módulo '{e.name}' ausente; instale com: pip install --user reportlab python-pptx "
                    "(ou gere em outra máquina com --render-only dados.json)")
            except Exception as e:  # noqa: BLE001
                log(f"falha ao gerar {name}: {e!r}")


def _csv(path: Path, header: list[str], rows: list[list[Any]]) -> None:
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(header)
        w.writerows(rows)


def finalize(d: dict, out: Path, customer: str, formats: list[str] | None = None) -> int:
    checks = evaluate(d)
    dom, overall = score(checks)
    pil, _ = score(checks, "pillar")
    pil = {p: pil[p] for p in PILLARS if p in pil}
    d["checks"], d["scores"], d["scores_pilar"], d["score_global"] = [asdict(x) for x in checks], dom, pil, overall
    out.mkdir(parents=True, exist_ok=True)
    (out / "dados.json").write_text(json.dumps(d, ensure_ascii=False, indent=1, default=str), encoding="utf-8")
    (out / "relatorio.html").write_text(build_report(d, checks, dom, pil, overall, customer), encoding="utf-8")
    _csv(out / "achados.csv", ["Prioridade", "Pilar", "Domínio", "Lacuna", "Evidência", "Impacto", "Recomendação"],
         [[c.severity, c.pillar, c.domain, c.title, c.evidence, c.impact, c.recommendation]
          for c in sorted((c for c in checks if c.passed is False), key=lambda c: SEV_ORDER[c.severity])])
    av = {0: "desconhecida", 1: "disponível", 2: "INDISPONÍVEL"}
    _csv(out / "cobertura_hosts.csv",
         ["Host", "Nome visível", "Host groups", "Proxy", "Status", "Em manutenção", "Disponibilidade", "Templates", "Itens habilitados", "Itens não suportados",
          "Itens < 60s", "Itens histórico > 90d", "NVPS estimado", "Triggers habilitadas", "Tags", "TLS", "Versão do agente", "Agent 2", "Erro de interface"],
         [[h["host"], h["name"], ", ".join(h["groups"]), h.get("proxy_nome", ""), "monitorado" if h["monitored"] else "desabilitado", yn(h["maint"]),
           av.get(h["avail"], "?"), ", ".join(h["templates"]), h.get("itens_hab", 0), h.get("itens_uns", 0), h.get("itens_agressivos", 0), h.get("itens_hist_longo", 0),
           str(h.get("nvps", 0)).replace(".", ","), h.get("trig_hab", 0), yn(h["tags"]), yn(h["tls"]), h.get("agente_versao", ""), yn(h.get("agente2")), h["erro_iface"]]
          for h in sorted(d["hosts"], key=lambda h: (not h["monitored"], h["avail"] != 2, h["name"]))])
    _csv(out / "cobertura_grupos.csv", ["Host group", "Hosts", "Monitorados", "Disponíveis", "Com template", "Com trigger", "Sem item não suportado", "Com tag", "TLS"],
         [[g, v["total"], v.get("monitorados", 0), v.get("disponiveis", 0), v.get("com_template", 0), v.get("com_trigger", 0), v.get("sem_nao_suportado", 0),
           v.get("com_tag", 0), v.get("com_tls", 0)] for g, v in d["coverage"].items()])
    _csv(out / "top_triggers.csv", ["Trigger", "Host", "Severidade", "Disparos", "MTTR mediano (min)", "MTTA mediano (min)", "Flapping"],
         [[t["trigger"], t["host"], t["sev"], t["disparos"], t["mttr_mediana_min"], t["mtta_mediana_min"], yn(t in d["events"]["flapping"])] for t in d["events"]["top_triggers"]])
    _csv(out / "higiene_otimizacao.csv", ["Categoria", "Tipo", "Objeto", "Grupo", "Detalhe", "Ação recomendada", "NVPS atual", "NVPS após ação"],
         [[o["categoria"], o["tipo"], o["nome"], o["grupo"], o["detalhe"], NVPS_RULES.get(o["categoria"], (0, ""))[1],
           "" if o["nvps_de"] is None else str(o["nvps_de"]).replace(".", ","), "" if o["nvps_para"] is None else str(o["nvps_para"]).replace(".", ",")]
          for o in d["hygiene"]["oportunidades"]])
    render_extras(d, checks, dom, pil, overall, out, customer, list(EXTRA_OUTPUTS) if formats is None else formats)
    log("Pilares: " + " · ".join(f"{k} {v}" for k, v in pil.items()))
    log(f"Concluído: score {overall}/100 · {d['meta'].get('chamadas_api', 0)} chamadas de leitura · saída em {out.resolve()}")
    return 0


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

PROBES = [("host.get", {"countOutput": True}, None), ("item.get", {"countOutput": True, "monitored": True}, None),
          ("trigger.get", {"countOutput": True}, None), ("problem.get", {"countOutput": True}, None),
          ("event.get", {"countOutput": True, "time_from": int(time.time()) - 3600}, None), ("alert.get", {"countOutput": True, "time_from": int(time.time()) - 86400}, None),
          ("proxy.get", {"countOutput": True}, None), ("action.get", {"countOutput": True}, None), ("mediatype.get", {"countOutput": True}, None),
          ("user.get", {"countOutput": True}, None), ("usergroup.get", {"countOutput": True}, None), ("script.get", {"countOutput": True}, None),
          ("usermacro.get", {"countOutput": True, "globalmacro": True}, None), ("role.get", {"countOutput": True}, (5, 2)),
          ("token.get", {"countOutput": True}, (5, 4)), ("settings.get", {"output": "extend"}, (5, 2)), ("housekeeping.get", {"output": "extend"}, (5, 2)),
          ("authentication.get", {"output": "extend"}, (5, 2)), ("hanode.get", {"countOutput": True}, (6, 0))]


def run_test(Z: Zabbix) -> int:
    sp = support_status(Z.ver)
    print(f"Conectado: {Z.url}\nVersão: {Z.version} (suporte {sp['status']}) · autenticação: {Z.auth_mode} · header Bearer: {Z._bearer}")
    for m, p, v in PROBES:
        if v and Z.ver < v:
            print(f"  {m:<20} n/a (requer {v[0]}.{v[1]}+)")
            continue
        try:
            r = Z.call(m, **p)
            print(f"  {m:<20} OK  {r if not isinstance(r, (dict, list)) else 'acessível'}")
        except ZbxError as e:
            print(f"  {m:<20} NEGADO  {clip(e.data or e.message, 90)}")
    print("Se algum método essencial aparecer NEGADO, use a role 'Assessment-ReadOnly' (Super admin + allow list *.get).")
    Z.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Assessment read-only de ambiente Zabbix (5.0–7.x)")
    ap.add_argument("--url", default=os.getenv("ZBX_URL"), help="URL do frontend ou do api_jsonrpc.php (ou ZBX_URL)")
    ap.add_argument("--token", default=os.getenv("ZBX_TOKEN"), help="API token (ou ZBX_TOKEN). Prefira a variável de ambiente")
    ap.add_argument("--user", default=os.getenv("ZBX_USER"), help="Usuário (ou ZBX_USER); senha via ZBX_PASSWORD ou prompt")
    ap.add_argument("--insecure", action="store_true", help="Não valida o certificado TLS (CA interna/self-signed)")
    ap.add_argument("--ca-bundle", default=os.getenv("ZBX_CA_BUNDLE"), help="Arquivo PEM da CA interna (alternativa ao --insecure)")
    ap.add_argument("--no-proxy", action="store_true", help="Ignora HTTP(S)_PROXY do ambiente (acesso direto pela VPN)")
    ap.add_argument("--timeout", type=int, default=180, help="Timeout por chamada (s)")
    ap.add_argument("--customer", default="Assaí Atacadista")
    ap.add_argument("--env-name", default="Produção", help="Nome do ambiente exibido no relatório")
    ap.add_argument("--groups", default=None, help="Host groups (curingas aceitos, separados por vírgula). Padrão: todos")
    ap.add_argument("--days", type=int, default=30, help="Janela de eventos/notificações (máx. 365)")
    ap.add_argument("--max-events-per-day", type=int, default=20000, help="Limite de eventos por dia na coleta")
    ap.add_argument("--expected-integrations", default="", help="Integrações esperadas, ex.: servicenow,teams,pagerduty")
    ap.add_argument("--threads", type=int, default=4, help="Chamadas paralelas (padrão 4; aumente com cautela)")
    ap.add_argument("--out", default=None)
    ap.add_argument("--test", action="store_true", help="Só testa conexão/permissões e sai")
    ap.add_argument("--render-only", default=None, help="Regera relatórios a partir de um dados.json existente (não conecta no Zabbix)")
    ap.add_argument("--formats", default="pdf,pptx", help="Saídas além de HTML/CSV/JSON: pdf, pptx ou 'none'")
    a = ap.parse_args()
    formats = [f.strip().lower() for f in a.formats.split(",") if f.strip() and f.strip().lower() != "none"]
    bad = [f for f in formats if f not in EXTRA_OUTPUTS]
    if bad:
        ap.error(f"--formats inválido: {', '.join(bad)} (opções: {', '.join(EXTRA_OUTPUTS)}, none)")

    if a.render_only:
        jf = Path(a.render_only)
        d = json.loads(jf.read_text(encoding="utf-8"))
        return finalize(d, Path(a.out) if a.out else jf.parent, a.customer, formats)

    if not a.url:
        ap.error("informe --url ou ZBX_URL")
    password = None
    if not a.token and a.user:
        password = os.getenv("ZBX_PASSWORD") or getpass.getpass(f"Senha do usuário {a.user}: ")
    if not a.token and not a.user:
        ap.error("informe ZBX_TOKEN (recomendado) ou ZBX_USER")
    try:
        Z = Zabbix(a.url, token=a.token, user=a.user, password=password, insecure=a.insecure, ca=a.ca_bundle, timeout=a.timeout, no_proxy=a.no_proxy)
    except ssl.SSLError as e:
        sys.exit(f"Erro TLS: {e}. Use --ca-bundle <ca.pem> ou --insecure.")
    except urllib.error.URLError as e:
        sys.exit(f"Sem conexão com {a.url}: {e.reason}. Verifique VPN/rota/DNS a partir desta máquina (e --no-proxy se houver proxy no ambiente).")
    except ZbxError as e:
        sys.exit(f"Falha de autenticação/API: {e}")
    try:
        Z.call("host.get", countOutput=True)
    except ZbxError as e:
        sys.exit(f"Credencial recusada pelo Zabbix ({clip(e.data or e.message, 120)}). Verifique token/usuário, expiração e se a role permite acesso à API.")
    log(f"Zabbix {Z.version} · auth={Z.auth_mode} · {Z.url}")
    if a.test:
        return run_test(Z)

    t0, days, threads = time.time(), max(1, min(a.days, 365)), max(1, a.threads)
    E = Errors()
    groups = [x for x in (a.groups or "").split(",") if x.strip()]
    try:
        log("plataforma (versão, HA, settings, housekeeping, autenticação)...")
        plat = collect_platform(Z, E)
        plat["proxies"], plat["proxy_groups"] = collect_proxies(Z, E)
        log("hosts...")
        hosts = collect_hosts(Z, E, threads, groups)
        log(f"{len(hosts)} hosts · templates...")
        templates = collect_templates(Z, E)
        log("itens (por lote de hosts)...")
        items = collect_items(Z, E, hosts, threads)
        log(f"{num(items['habilitados'])} itens habilitados · LLD...")
        lld = collect_lld(Z, E, hosts, threads)
        log("triggers...")
        trig = collect_triggers(Z, E, hosts, threads)
        log("problemas abertos...")
        probs = collect_problems(Z, E)
        log(f"eventos de {days} dias...")
        evs, trunc = collect_events(Z, E, days, threads, a.max_events_per_day)
        log("notificações, ações, usuários, tokens, scripts, macros, manutenção, web, serviços...")
        alerts = collect_alerts(Z, E, days)
        cfg = collect_config(Z, E)
        log("versões de agente e self-monitoring...")
        agents = collect_agents(Z, E)
        internal = collect_internal(Z, E)
    finally:
        Z.close()

    if groups:  # restringe problemas/eventos aos hosts do escopo
        tset = {t for t, v in trig.items()}
        probs = [p for p in probs if p.get("objectid") in tset]
        evs = [e for e in evs if e["t"] in tset]
    url_host = re.sub(r"^https?://", "", Z.url).split("/")[0]
    d: dict[str, Any] = {"meta": {"days": days, "coleta": {}, "gerado_em": datetime.now().strftime("%d/%m/%Y %H:%M"), "ambiente": a.env_name,
                                  "url_host": url_host, "auth": Z.auth_mode, "escopo_grupos": ", ".join(groups),
                                  "expected_integrations": [x.strip().lower() for x in a.expected_integrations.split(",") if x.strip()]},
                         "platform": plat, "hosts": hosts}
    plat["interno"] = parse_internal(internal, {h["id"]: h["name"] for h in hosts})
    v64 = Z.ver >= (6, 4)
    srv_mm = Z.ver
    linked = {tid for h in hosts for tid in h["templateids"]}

    def vend_old(t):
        m = re.match(r"(\d+)\.(\d+)", t["vendor_version"] or "")
        return bool(m) and (int(m.group(1)), int(m.group(2))) < srv_mm

    custom = [t for t in templates if ((not t["vendor"]) if v64 else not t["name"].startswith("Template "))]
    d["templates_resumo"] = {"total": len(templates), "em_uso": sum(1 for t in templates if t["id"] in linked), "custom": len(custom),
                             "custom_sem_uso": sum(1 for t in custom if not t["hosts"] and not t["em_templates"]),
                             "vendor_desatualizados": sum(1 for t in templates if t["vendor"] == "Zabbix" and t["id"] in linked and vend_old(t)) if v64 else None,
                             "legados_em_uso": sum(1 for t in templates if t["name"].startswith("Template ") and t["id"] in linked)}
    d["items"] = {k: items[k] for k in ("total", "habilitados", "nao_suportados", "agressivos", "hist_longo", "descobertos", "intervalo_macro")}
    d["items"].update({"nvps_estimado": round(items["nvps"], 1), "por_tipo": {ITEM_TYPES.get(k, str(k)): v for k, v in items["por_tipo"].most_common()},
                       "erros": items["erros"].most_common(15)})
    d["lld"] = lld
    summarize_triggers(d, trig)
    summarize_problems(d, probs)
    d["meta"]["days"] = days
    summarize_events(d, evs, trunc)
    summarize_config(d, cfg, alerts)
    build_hygiene(d, items["por_host"], templates)
    compute_coverage(d, agents)
    for h in d["hosts"]:
        h.pop("templateids", None)
    d.pop("_trig_names", None)
    keys = ["ha", "settings", "housekeeping", "authentication", "proxies", "proxy_groups", "hosts", "templates", "items", "lld", "triggers", "problems",
            "events", "alerts", "actions", "mediatypes", "users", "roles", "usergroups", "tokens", "scripts", "macros", "maintenance", "web", "discovery",
            "services", "dashboards", "reports", "connectors", "agents", "self_monitoring"]
    d["meta"]["coleta"] = {k: E.status(k) for k in keys}
    d["meta"]["chamadas_api"] = Z.stats["calls"]
    d["meta"]["duracao_s"] = round(time.time() - t0)
    out = Path(a.out or f"zabbix-assessment-{datetime.now():%Y%m%d-%H%M}")
    return finalize(d, out, a.customer, formats)


if __name__ == "__main__":
    sys.exit(main())
