#!/usr/bin/env python3
# ============================================================
# Linux Infra Audit Tool v1.0 — Python Edition
# Auditoría de saturación para servidores web/BD (cPanel, Ubuntu, etc.)
# Compatible: CentOS 7/8, RHEL 8, AlmaLinux/CloudLinux 8, Ubuntu 20/22, Debian 10/11
#
# Uso  : python3 infra_audit.py
# Root : requerido
# Out  : /root/infra_audit_FECHA.txt  +  /root/migrate_myisam.sql
#
# CARACTERÍSTICAS:
#  - Lee procesos directamente de /proc (sin depender de ps) con
#    parsing robusto de /proc/<pid>/stat (comm con espacios/paréntesis,
#    campos negativos como tpgid=-1 en daemons).
#  - CPU% INSTANTÁNEO (delta entre 2 muestras de 1s) + promedio de
#    vida del proceso como columna de contexto.
#  - TOP procesos y TOP usuarios por CPU/RAM (identifica la cuenta
#    que satura en servidores compartidos).
#  - Conexiones establecidas a :80/:443 por IP (detecta floods/bots).
#  - MySQL/MariaDB: processlist, queries lentas, buffer pool vs datos,
#    tablas MyISAM (genera script de migración a InnoDB), MySQLTuner.
#  - PHP-FPM: workers y RAM real, pools cPanel por max_children,
#    slow logs por usuario (/var/cpanel/php-fpm/{user}/logs/slow.log).
#  - Disco: uso, inodos, latencia I/O por dispositivo (/proc/diskstats,
#    con soporte NVMe validando contra /sys/block/).
#  - CloudLinux: LVE (lvectl/lveinfo) y DB Governor (usuarios
#    restringidos por consumo MySQL).
#  - RAM/Swap/OOM killer, Apache/Nginx, cola Exim, seguridad básica,
#    servicios systemd y logs recientes. Resumen ejecutivo al final.
# ============================================================

import subprocess, os, sys, re, socket, shutil, platform
import datetime, glob, time

# ---------- Config ----------
TS       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
OUT_FILE = f"/root/infra_audit_{TS}.txt"
SQL_FILE = "/root/migrate_myisam_to_innodb.sql"
TUNER    = "/root/mysqltuner.pl"
TUNER_URL= "https://raw.githubusercontent.com/major/MySQLTuner-perl/master/mysqltuner.pl"

FINDINGS = {"critical": [], "warning": [], "ok": [], "rec": []}
LINES    = []
ANSI     = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

class C:
    RED="\033[1;31m"; YELLOW="\033[1;33m"; GREEN="\033[1;32m"
    BLUE="\033[1;34m"; CYAN="\033[1;36m"; BOLD="\033[1m"; RESET="\033[0m"

# ============================================================
# HELPERS BÁSICOS
# ============================================================
def w(t=""):
    print(t); LINES.append(t)

def sep(title):
    w(f"\n{'═'*62}\n  {title}\n{'═'*62}")

def sub(title):
    pad = max(0, 54 - len(title))
    w(f"\n  ── {title} {'─'*pad}")

def ok(m):   w(f"{C.GREEN} ✔  {m}{C.RESET}");  FINDINGS["ok"].append(m)
def warn(m): w(f"{C.YELLOW} ⚠  {m}{C.RESET}"); FINDINGS["warning"].append(m)
def crit(m): w(f"{C.RED} ✘  {m}{C.RESET}");    FINDINGS["critical"].append(m)
def info(m): w(f"{C.BLUE} ℹ  {m}{C.RESET}")
def rec(m):  w(f"{C.CYAN} →  {m}{C.RESET}");   FINDINGS["rec"].append(m)

def run(cmd, timeout=30):
    try:
        r = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout)
        return (r.stdout or b"").decode("utf-8", errors="replace").strip(), r.returncode
    except Exception:
        return "", 1

def has(cmd):
    return shutil.which(cmd) is not None

def save():
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        for line in LINES:
            f.write(ANSI.sub("", line) + "\n")

def meminfo_dict():
    d = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    d[parts[0].rstrip(":")] = int(parts[1])
    except Exception:
        pass
    return d

# ============================================================
# LEER PROCESOS DIRECTAMENTE DE /proc — Sin depender de ps aux
# ------------------------------------------------------------
# NOTA: parsing robusto. En /proc/<pid>/stat el campo comm va entre
# paréntesis y puede contener espacios y ')' — se separa por el
# ÚLTIMO ')'. Campos posteriores pueden ser NEGATIVOS (tpgid=-1 en
# daemons), por lo que jamás usar \d+ para saltarlos.
# Índices tras el ')': [0]=state [1]=ppid ... [11]=utime [12]=stime
# [19]=starttime  (man proc(5): campos 3..22 del stat completo)
# ============================================================
_PROC_CACHE = None

def _read_proc_sample():
    """Un muestreo crudo de /proc: pid -> {comm,state,utime,stime,starttime}."""
    sample = {}
    for pid_dir in glob.glob("/proc/[0-9]*"):
        try:
            pid = int(os.path.basename(pid_dir))
            raw = open(f"/proc/{pid}/stat").read()
            lp, rp = raw.find("("), raw.rfind(")")
            if lp < 0 or rp < 0:
                continue
            comm = raw[lp+1:rp]
            rest = raw[rp+1:].split()
            if len(rest) < 20:
                continue
            sample[pid] = {
                "comm": comm,
                "state": rest[0],
                "utime": int(rest[11]),
                "stime": int(rest[12]),
                "starttime": int(rest[19]),
            }
        except Exception:
            continue
    return sample

def read_procs(sample_interval=1.0, cached=True):
    """
    Devuelve lista de dicts: pid, user, cmd, comm, state, rss_mb,
    cpu_pct (INSTANTÁNEO, delta de 1s), cpu_avg (promedio de vida).
    cached=True reutiliza el muestreo de la primera llamada para no
    dormir 1s en cada sección.
    """
    global _PROC_CACHE
    if cached and _PROC_CACHE is not None:
        return _PROC_CACHE

    try:
        hz = os.sysconf("SC_CLK_TCK")
    except (ValueError, OSError, AttributeError):
        hz = 100
    try:
        uptime_s = float(open("/proc/uptime").read().split()[0])
    except Exception:
        uptime_s = 1.0

    s1 = _read_proc_sample()
    time.sleep(sample_interval)
    s2 = _read_proc_sample()

    uid_cache, procs = {}, []
    for pid, d in s2.items():
        try:
            status_raw = open(f"/proc/{pid}/status").read()
            uid_m  = re.search(r"^Uid:\s+(\d+)", status_raw, re.M)
            rss_m  = re.search(r"^VmRSS:\s+(\d+)", status_raw, re.M)
            uid    = int(uid_m.group(1)) if uid_m else 0
            rss_kb = int(rss_m.group(1)) if rss_m else 0

            try:
                cmdline = open(f"/proc/{pid}/cmdline").read().replace("\x00", " ").strip()
                cmd     = cmdline[:80] if cmdline else f"[{d['comm']}]"
            except Exception:
                cmd = f"[{d['comm']}]"

            if uid not in uid_cache:
                try:
                    import pwd
                    uid_cache[uid] = pwd.getpwuid(uid).pw_name
                except Exception:
                    uid_cache[uid] = str(uid)
            user = uid_cache[uid]

            # CPU instantáneo: delta entre las 2 muestras.
            # Se valida starttime para no comparar contra un PID reciclado.
            if pid in s1 and s1[pid]["starttime"] == d["starttime"]:
                delta_ticks = (d["utime"] + d["stime"]) - (s1[pid]["utime"] + s1[pid]["stime"])
                cpu_now = round(max(delta_ticks, 0) / hz / sample_interval * 100, 1)
            else:
                cpu_now = 0.0  # proceso nuevo durante el muestreo

            # CPU promedio desde que arrancó el proceso (contexto)
            proc_time_s = (d["utime"] + d["stime"]) / hz
            elapsed_s   = max(uptime_s - d["starttime"] / hz, 0.01)
            cpu_avg     = round(proc_time_s / elapsed_s * 100, 1)

            procs.append({
                "pid": pid, "user": user, "state": d["state"],
                "rss_mb": round(rss_kb / 1024, 1),
                "cpu_pct": cpu_now, "cpu_avg": cpu_avg,
                "cmd": cmd, "comm": d["comm"],
            })
        except Exception:
            continue

    _PROC_CACHE = procs
    return procs

def get_memtotal_mb():
    mem = meminfo_dict()
    return mem.get("MemTotal", 1) // 1024

# ============================================================
# HEADER
# ============================================================
def header():
    host = socket.gethostname()
    now  = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        ip = "N/A"
    w(); w("═"*62)
    w(f"   LINUX INFRA AUDIT TOOL v1.0")
    w(f"   Auditoría de Infraestructura y Saturación")
    w(f"   Servidor : {host}")
    w(f"   IP       : {ip}")
    w(f"   Fecha    : {now}")
    w(f"   OS       : {platform.system()} {platform.release()}")
    w(f"   Python   : {platform.python_version()}")
    w("═"*62)

# ============================================================
# 1. QUÉ CONSUME RECURSOS AHORA
# ============================================================
def check_top_consumers():
    sep("1. ¿QUÉ CONSUME RECURSOS AHORA?")
    w(f"\n{C.BOLD}  Primer punto a revisar cuando el servidor se satura.{C.RESET}")

    try:
        loads = open("/proc/loadavg").read().split()
        l1, l5, l15 = loads[0], loads[1], loads[2]
    except Exception:
        l1, l5, l15 = "0", "0", "0"
    cores_out, _ = run("nproc")
    cores = int(cores_out) if cores_out.isdigit() else 1

    sub("LOAD AVERAGE vs NÚCLEOS")
    w(f"  Núcleos CPU  : {cores}")
    l1f = float(l1)
    color_l = C.RED if l1f > cores else (C.YELLOW if l1f > cores * 0.7 else C.GREEN)
    w(f"  Load (1 min) : {color_l}{l1}{C.RESET}  {'⚠ SATURADO' if l1f > cores else ('↑ Elevado' if l1f > cores*0.7 else '✔ Normal')}")
    w(f"  Load (5 min) : {l5}")
    w(f"  Load (15 min): {l15}")

    bar_len = 40
    bar_fill = min(int(bar_len * l1f / max(cores, 1)), bar_len)
    bar_color = C.RED if l1f > cores else (C.YELLOW if l1f > cores * 0.7 else C.GREEN)
    bar = f"{bar_color}{'█'*bar_fill}{'░'*(bar_len-bar_fill)}{C.RESET}"
    w(f"  [{bar}] {l1}/{cores}")

    if l1f > cores * 1.5:
        crit(f"Load Average crítico ({l1}) — servidor saturado")
        rec("Identificar proceso: ver sección de consumo por servicio abajo")
        rec("Queries MySQL: mysql -e \"SHOW FULL PROCESSLIST;\"")
    elif l1f > cores * 0.8:
        warn(f"Load Average elevado ({l1}) para {cores} núcleo/s")
    else:
        ok(f"Load Average normal ({l1} sobre {cores} núcleo/s)")

    # Leer procesos de /proc (2 muestras de 1s → CPU instantáneo)
    sub("LEYENDO PROCESOS DEL SISTEMA (vía /proc — sin depender de ps)")
    info("Tomando 2 muestras con 1s de intervalo para CPU instantáneo...")
    procs = read_procs()
    total_mem_mb = get_memtotal_mb()

    if not procs:
        warn("No se pudieron leer procesos de /proc")
        ps_out, _ = run("ps aux 2>/dev/null || ps -ef 2>/dev/null")
        if ps_out:
            w(ps_out[:3000])
        return {"cores": cores, "load1": l1f}

    info(f"Procesos leídos: {len(procs)}")

    # TOP 15 por CPU (instantáneo)
    sub("TOP 15 PROCESOS POR CPU (instantáneo, ventana de 1s)")
    top_cpu = sorted(procs, key=lambda x: x["cpu_pct"], reverse=True)[:15]
    w(f"  {C.BOLD}{'PID':<8} {'USUARIO':<15} {'CPU%':>6} {'CPUVIDA':>8} {'RAM MB':>8}  {'EST':>3}  PROCESO{C.RESET}")
    w(f"  {'─'*70}")
    for p in top_cpu:
        color = C.RED if p["cpu_pct"] > 50 else (C.YELLOW if p["cpu_pct"] > 20 else C.RESET)
        w(f"  {color}{p['pid']:<8} {p['user']:<15} {p['cpu_pct']:>6.1f} {p['cpu_avg']:>7.1f}% {p['rss_mb']:>8.1f}  {p['state']:>3}  {p['cmd'][:40]}{C.RESET}")

    # TOP 15 por RAM
    sub("TOP 15 PROCESOS POR RAM")
    top_ram = sorted(procs, key=lambda x: x["rss_mb"], reverse=True)[:15]
    w(f"  {C.BOLD}{'PID':<8} {'USUARIO':<15} {'CPU%':>6} {'RAM MB':>8}  {'RAM%':>6}  PROCESO{C.RESET}")
    w(f"  {'─'*62}")
    for p in top_ram:
        ram_pct = round(p["rss_mb"] / max(total_mem_mb, 1) * 100, 1)
        color = C.RED if ram_pct > 10 else (C.YELLOW if ram_pct > 5 else C.RESET)
        w(f"  {color}{p['pid']:<8} {p['user']:<15} {p['cpu_pct']:>6.1f} {p['rss_mb']:>8.1f}  {ram_pct:>5.1f}%  {p['cmd'][:40]}{C.RESET}")

    # TOP usuarios — en cPanel identifica la CUENTA que satura
    sub("TOP 10 USUARIOS POR CONSUMO (identifica la cuenta cPanel)")
    users = {}
    for p in procs:
        u = users.setdefault(p["user"], {"n": 0, "cpu": 0.0, "ram": 0.0})
        u["n"]   += 1
        u["cpu"] += p["cpu_pct"]
        u["ram"] += p["rss_mb"]
    top_users = sorted(users.items(), key=lambda kv: (kv[1]["cpu"], kv[1]["ram"]), reverse=True)[:10]
    w(f"  {C.BOLD}{'USUARIO':<20} {'PROCS':>6} {'CPU% TOTAL':>12} {'RAM MB':>10}{C.RESET}")
    w(f"  {'─'*52}")
    for name, u in top_users:
        color = C.RED if u["cpu"] > 80 else (C.YELLOW if u["cpu"] > 40 else C.RESET)
        w(f"  {color}{name:<20} {u['n']:>6} {u['cpu']:>11.1f}% {u['ram']:>10.1f}{C.RESET}")
        if u["cpu"] > 80 and name not in ("root", "mysql"):
            crit(f"Usuario '{name}' consumiendo {u['cpu']:.0f}% CPU — cuenta sospechosa de saturar")
            rec(f"Ver sus procesos: ps -u {name} -o pid,pcpu,pmem,etime,cmd --sort=-pcpu | head")
            rec(f"Si es CloudLinux: lvectl list | grep $(id -u {name})")

    # Agrupar por servicio
    sub("CONSUMO POR SERVICIO (lectura /proc)")
    service_patterns = [
        ("MySQL/MariaDB",   ["mysqld", "mariadbd"]),
        ("Apache/httpd",    ["httpd", "apache2"]),
        ("Nginx",           ["nginx"]),
        ("PHP-FPM",         ["php-fpm", "php7", "php8"]),
        ("Exim",            ["exim"]),
        ("Dovecot",         ["dovecot", "imap", "pop3"]),
        ("Imunify360",      ["imunify", "aibolit"]),
        ("Wazuh",           ["wazuh", "ossec"]),
        ("Redis",           ["redis-server", "redis"]),
        ("Java/Solr",       ["java"]),
        ("Teleport",        ["teleport"]),
        ("cPanel/WHM",      ["cpanel", "whostmgr", "cpsrvd", "queueprocd"]),
        ("SpamAssassin",    ["spamd", "spamassassin"]),
        ("Tailwatchd",      ["tailwatchd"]),
        ("JetBackup",       ["jetbackup", "jetmongod"]),
        ("ClamAV",          ["clamd", "clamav", "freshclam"]),
        ("Backups/rsync",   ["rsync", "tar ", "gzip", "pigz"]),
    ]

    w(f"\n  {C.BOLD}{'SERVICIO':<22} {'PROCS':>6} {'CPU% TOTAL':>12} {'RAM TOTAL MB':>14}  {'RAM%':>6}{C.RESET}")
    w(f"  {'─'*66}")
    found_any = False
    for name, patterns in service_patterns:
        matched = [p for p in procs if any(pat in p["cmd"].lower() or pat in p["comm"].lower() for pat in patterns)]
        if not matched:
            continue
        found_any = True
        total_cpu = round(sum(p["cpu_pct"] for p in matched), 1)
        total_ram = round(sum(p["rss_mb"] for p in matched), 1)
        ram_pct   = round(total_ram / max(total_mem_mb, 1) * 100, 1)
        color = C.RED if total_cpu > 80 or total_ram > 1000 else \
                (C.YELLOW if total_cpu > 40 or total_ram > 400 else C.GREEN)
        w(f"  {color}{name:<22} {len(matched):>6} {total_cpu:>11.1f}% {total_ram:>13.1f}  {ram_pct:>5.1f}%{C.RESET}")
        if total_cpu > 80:
            crit(f"{name} consumiendo {total_cpu}% CPU — principal sospechoso de saturación")
        elif total_cpu > 50:
            warn(f"{name} con alto consumo de CPU: {total_cpu}%")
    if not found_any:
        info("No se identificaron servicios conocidos (servidor puede ser mínimo)")

    # Procesos en estado D
    sub("PROCESOS BLOQUEADOS EN I/O (estado D)")
    proc_d = [p for p in procs if p["state"] == "D"]
    if proc_d:
        crit(f"{len(proc_d)} proceso(s) en estado D — bloqueados esperando I/O o lock de BD")
        w(f"  {C.BOLD}{'PID':<8} {'USUARIO':<15} {'RAM MB':>8}  PROCESO{C.RESET}")
        for p in proc_d:
            w(f"  {C.RED}{p['pid']:<8} {p['user']:<15} {p['rss_mb']:>8.1f}  {p['cmd'][:50]}{C.RESET}")
        rec("Verificar I/O: iotop -o -b -n 3  (o: cat /proc/diskstats)")
        rec("Verificar locks MySQL: mysql -e \"SHOW FULL PROCESSLIST;\"")
    else:
        ok("No hay procesos bloqueados en estado D")

    # Procesos zombie
    sub("PROCESOS ZOMBIE (estado Z)")
    proc_z = [p for p in procs if p["state"] == "Z"]
    if proc_z:
        warn(f"{len(proc_z)} proceso(s) zombie detectados")
        for p in proc_z:
            w(f"  {C.YELLOW}PID {p['pid']} — {p['cmd'][:60]}{C.RESET}")
        rec("Identificar proceso padre y reiniciarlo")
    else:
        ok("No hay procesos zombie")

    # Conexiones web por IP — floods/ataques saturan Apache y PHP-FPM
    sub("CONEXIONES ESTABLECIDAS A :80/:443 POR IP (detecta floods)")
    conns, rc = run("ss -Htn state established '( sport = :80 or sport = :443 )' 2>/dev/null "
                    "| awk '{print $4}' | sed 's/.*[]:]//;s/^\\[//' "
                    "| sort | uniq -c | sort -rn | head -12")
    if rc != 0 or not conns:
        conns, _ = run("netstat -tn 2>/dev/null | grep -E ':(80|443) ' | grep ESTABLISHED "
                       "| awk '{print $5}' | sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | head -12")
    if conns:
        total_conn, _ = run("ss -Htn state established '( sport = :80 or sport = :443 )' 2>/dev/null | wc -l")
        info(f"Conexiones web establecidas: {(total_conn or '?').strip()}")
        w(conns)
        for line in conns.splitlines():
            p = line.strip().split()
            if len(p) >= 2 and p[0].isdigit() and int(p[0]) > 100:
                crit(f"IP {p[1]} con {p[0]} conexiones simultáneas — posible flood o bot")
                rec(f"Verificar en domlogs: grep -c '{p[1]}' /var/log/apache2/domlogs/* 2>/dev/null | grep -v ':0' | sort -t: -k2 -rn | head")
                rec(f"Bloquear si es abusiva: csf -d {p[1]}")
    else:
        info("Sin conexiones web establecidas o ss/netstat no disponibles")

    return {"cores": cores, "load1": l1f}

# ============================================================
# 2. RECURSOS (RAM / SWAP / CPU)
# ============================================================
def check_resources():
    sep("2. RECURSOS DEL SISTEMA (RAM / SWAP / CPU)")

    mem = meminfo_dict()
    total_mb = mem.get("MemTotal", 0) // 1024
    free_mb  = mem.get("MemFree",  0) // 1024
    avail_mb = mem.get("MemAvailable", 0) // 1024
    cache_mb = (mem.get("Cached", 0) + mem.get("Buffers", 0)) // 1024
    used_mb  = total_mb - free_mb - cache_mb
    ram_pct  = round(used_mb * 100 / max(total_mb, 1))

    sub("RAM")
    w(f"  Total       : {total_mb:>8} MB")
    w(f"  Usada real  : {used_mb:>8} MB  ({ram_pct}%)")
    w(f"  Cache/Buffer: {cache_mb:>8} MB  (liberables)")
    w(f"  Disponible  : {avail_mb:>8} MB")

    bar_fill = int(40 * ram_pct / 100)
    color = C.RED if ram_pct >= 90 else (C.YELLOW if ram_pct >= 75 else C.GREEN)
    bar = f"{color}{'█'*bar_fill}{'░'*(40-bar_fill)}{C.RESET}"
    w(f"  [{bar}] {ram_pct}%")

    if ram_pct >= 95:
        crit(f"RAM al {ram_pct}% — riesgo de OOM killer inminente")
        rec("Reducir pm.max_children PHP-FPM y/o innodb_buffer_pool_size MySQL")
    elif ram_pct >= 85:
        warn(f"RAM al {ram_pct}% — margen ajustado")
    else:
        ok(f"RAM al {ram_pct}% — normal")

    # OOM killer reciente — evidencia directa de falta de RAM
    sub("EVENTOS OOM KILLER (kernel)")
    oom, _ = run("dmesg -T 2>/dev/null | grep -i 'killed process' | tail -5")
    if not oom:
        oom, _ = run("journalctl -k --since '7 days ago' --no-pager 2>/dev/null | grep -i 'killed process' | tail -5")
    if oom:
        crit("El kernel ha matado procesos por falta de RAM (OOM):")
        w(f"{C.RED}{oom}{C.RESET}")
        rec("Reducir consumo (PHP-FPM/MySQL) o ampliar RAM — el OOM ya actuó")
    else:
        ok("Sin eventos OOM killer recientes en dmesg/journal")

    sub("SWAP")
    swap_total = mem.get("SwapTotal", 0) // 1024
    swap_free  = mem.get("SwapFree",  0) // 1024
    swap_used  = swap_total - swap_free

    if swap_total == 0:
        crit("Swap no configurado — ante pico de RAM el OOM killer actúa")
        rec("fallocate -l 4G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile")
        rec("(en XFS/CoW usar: dd if=/dev/zero of=/swapfile bs=1M count=4096)")
        rec("echo '/swapfile none swap sw 0 0' >> /etc/fstab")
    else:
        swap_pct = round(swap_used * 100 / max(swap_total, 1))
        color = C.RED if swap_pct >= 80 else (C.YELLOW if swap_pct >= 30 else C.GREEN)
        w(f"  Total: {swap_total} MB | Usado: {swap_used} MB | Pct: {color}{swap_pct}%{C.RESET}")
        if swap_pct >= 80:
            crit(f"Swap al {swap_pct}% — disco usado como RAM, rendimiento muy degradado")
            rec("Reducir PHP-FPM max_children y MySQL buffer pool")
            rec("swapoff -a && swapon -a  (tras reducir el uso de RAM)")
        elif swap_pct >= 30:
            warn(f"Swap en uso: {swap_used} MB de {swap_total} MB ({swap_pct}%)")
        else:
            ok(f"Swap configurado ({swap_total} MB), uso bajo ({swap_pct}%)")

    sub("CPU E I/O")
    cores_out, _ = run("nproc")
    cpu_model, _ = run("grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs 2>/dev/null")
    uptime_out, _ = run("uptime 2>/dev/null")
    info(f"Modelo : {cpu_model or 'N/A'}")
    info(f"Núcleos: {cores_out or '?'}")
    info(f"Uptime : {uptime_out or 'N/A'}")

    # I/O wait — leer de /proc/stat directamente
    try:
        stat1 = open("/proc/stat").readline().split()
        time.sleep(1)
        stat2 = open("/proc/stat").readline().split()
        total1  = sum(int(x) for x in stat1[1:])
        total2  = sum(int(x) for x in stat2[1:])
        iowait1 = int(stat1[5]) if len(stat1) > 5 else 0
        iowait2 = int(stat2[5]) if len(stat2) > 5 else 0
        diff_total = max(total2 - total1, 1)
        wa_pct = round((iowait2 - iowait1) * 100 / diff_total, 1)
        color = C.RED if wa_pct >= 30 else (C.YELLOW if wa_pct >= 15 else C.GREEN)
        w(f"  I/O Wait: {color}{wa_pct}%{C.RESET}  {'⚠ Disco saturado' if wa_pct >= 30 else ('↑ Moderado' if wa_pct >= 15 else '✔ Normal')}")
        if wa_pct >= 30:
            crit(f"I/O Wait alto ({wa_pct}%) — disco o BD bloqueando procesos")
            rec("Verificar: cat /proc/diskstats  o  iotop -o -b -n 3")
            rec("Verificar queries MySQL bloqueadas: mysql -e \"SHOW FULL PROCESSLIST;\"")
        elif wa_pct >= 15:
            warn(f"I/O Wait moderado ({wa_pct}%)")
        else:
            ok(f"I/O Wait normal ({wa_pct}%)")
    except Exception as e:
        info(f"I/O Wait: no disponible ({e})")

    return {"total_mb": total_mb}

# ============================================================
# 3. DISCO
# ============================================================
def check_disk():
    sep("3. DISCO")

    sub("USO DE PARTICIONES")
    try:
        with open("/proc/mounts") as f:
            mounts = [line.split() for line in f if len(line.split()) >= 2]
        seen_dev = set()
        w(f"  {C.BOLD}{'Montaje':<20} {'Total':>10} {'Usado':>10} {'Libre':>10} {'Uso%':>6}{C.RESET}")
        w(f"  {'─'*60}")
        for m in mounts:
            dev, mount = m[0], m[1]
            if dev in seen_dev or not mount.startswith("/") or dev.startswith("tmpfs"):
                continue
            if any(x in mount for x in ["/proc", "/sys", "/dev", "/run"]):
                continue
            try:
                st = os.statvfs(mount)
                total_b = st.f_blocks * st.f_frsize
                avail_b = st.f_bavail * st.f_frsize   # coincide con 'Avail' de df
                used_b  = total_b - (st.f_bfree * st.f_frsize)
                pct     = round(used_b * 100 / max(total_b, 1))
                def fmt(b): return f"{b/(1024**3):.1f}G" if b >= 1024**3 else f"{b/(1024**2):.0f}M"
                color = C.RED if pct >= 90 else (C.YELLOW if pct >= 80 else C.GREEN)
                w(f"  {color}{mount:<20} {fmt(total_b):>10} {fmt(used_b):>10} {fmt(avail_b):>10} {pct:>5}%{C.RESET}")
                seen_dev.add(dev)
                if pct >= 90:
                    crit(f"Disco al {pct}% en {mount}")
                    rec(f"Liberar espacio: du -sh {mount}/* 2>/dev/null | sort -rh | head -20")
                elif pct >= 80:
                    warn(f"Disco al {pct}% en {mount}")
                else:
                    ok(f"Disco al {pct}% en {mount}")
            except Exception:
                continue
    except Exception:
        df_out, _ = run("df -h 2>/dev/null | grep -v tmpfs | grep -v devtmpfs")
        w(df_out or "  (no disponible)")

    # Inodos — un disco puede tener espacio pero quedarse sin inodos (colas de mail, sesiones PHP)
    sub("INODOS")
    inode_out, _ = run("df -i 2>/dev/null | grep -vE 'tmpfs|devtmpfs|Filesystem' | awk '$5+0 >= 80 {print}'")
    if inode_out:
        crit("Particiones con inodos >= 80%:")
        w(f"{C.RED}{inode_out}{C.RESET}")
        rec("Buscar directorios con millones de archivos: find /home -xdev -type d -size +1M 2>/dev/null")
    else:
        ok("Uso de inodos normal en todas las particiones")

    sub("I/O POR DISPOSITIVO (de /proc/diskstats)")
    try:
        def whole_disks(lines):
            """Un dispositivo es disco completo si existe /sys/block/<name>
            (un filtro por dígito final excluiría nvme0n1, mmcblk0, md0...)."""
            out = {}
            for line in lines:
                p = line.split()
                if len(p) < 14:
                    continue
                name = p[2]
                if name.startswith(("loop", "ram", "zram", "dm-")):
                    continue
                if not os.path.exists(f"/sys/block/{name}"):
                    continue  # es partición, no disco completo
                out[name] = {"reads": int(p[3]), "writes": int(p[7]), "io_ms": int(p[12])}
            return out

        with open("/proc/diskstats") as f:
            disks1 = whole_disks(f.readlines())
        time.sleep(1)
        with open("/proc/diskstats") as f:
            disks2 = whole_disks(f.readlines())

        w(f"  {C.BOLD}{'Dispositivo':<15} {'Lecturas/s':>12} {'Escrituras/s':>14} {'I/O ms':>10}{C.RESET}")
        w(f"  {'─'*55}")
        for dev in disks1:
            if dev in disks2:
                reads  = disks2[dev]["reads"]  - disks1[dev]["reads"]
                writes = disks2[dev]["writes"] - disks1[dev]["writes"]
                io_ms  = disks2[dev]["io_ms"]  - disks1[dev]["io_ms"]
                color  = C.RED if io_ms > 500 else (C.YELLOW if io_ms > 200 else C.RESET)
                w(f"  {color}{dev:<15} {reads:>12} {writes:>14} {io_ms:>10} ms{C.RESET}")
                if io_ms > 500:
                    crit(f"Dispositivo {dev} con alta latencia I/O ({io_ms} ms en 1s de muestreo)")
                    rec("Verificar: iotop -o -b -n 5  o  iostat -x 1 3")
    except Exception:
        info("I/O por dispositivo: no disponible vía /proc/diskstats")
        iostat_out, _ = run("iostat -dx 1 2 2>/dev/null | tail -15")
        if iostat_out:
            w(iostat_out)

# ============================================================
# 4. MYSQL
# ============================================================
def mysql_q(sql, timeout=15):
    out, rc = run(f'mysql --connect-timeout=5 -e "{sql}" 2>/dev/null', timeout=timeout)
    return out if rc == 0 else ""

def check_mysql():
    sep("4. MYSQL / MARIADB")

    if not has("mysql") and not has("mariadb"):
        info("MySQL/MariaDB no instalado"); return 0

    test, rc = run("mysqladmin --connect-timeout=5 status 2>/dev/null", timeout=10)
    if rc != 0:
        crit("MySQL/MariaDB no responde o no está activo")
        rec("systemctl status mysql || systemctl status mysqld")
        rec("Ver logs: tail -50 /var/log/mysqld.log   (MySQL 8 / cPanel AlmaLinux)")
        rec("En Ubuntu/Ploi: tail -50 /var/log/mysql/error.log")
        return 0

    ok("MySQL/MariaDB activo")
    info(test)

    # Queries activas — LO MÁS IMPORTANTE PRIMERO
    sub("QUERIES ACTIVAS AHORA (FULL PROCESSLIST)")
    proc = mysql_q("SELECT ID,USER,HOST,DB,COMMAND,TIME,STATE,LEFT(INFO,100) AS QUERY "
                   "FROM information_schema.PROCESSLIST "
                   "WHERE COMMAND != 'Sleep' ORDER BY TIME DESC LIMIT 25;")
    if proc:
        w(proc)
    else:
        ok("Sin queries activas (solo conexiones Sleep)")

    sub("QUERIES LENTAS ACTIVAS (> 10 segundos)")
    slow = mysql_q("SELECT ID,USER,TIME,STATE,LEFT(INFO,100) AS QUERY "
                   "FROM information_schema.PROCESSLIST "
                   "WHERE TIME > 10 AND COMMAND NOT IN ('Sleep','Daemon') "
                   "ORDER BY TIME DESC;")
    if slow and "ID" in slow:
        crit("Queries lentas activas detectadas:")
        w(f"{C.RED}{slow}{C.RESET}")
        rec("Matar query: mysql -e \"KILL <ID>;\"  (⚠ verificar antes qué hace la query — matar un ALTER/backup puede dejar tablas a medias)")
        rec("Analizar con EXPLAIN: mysql -e \"EXPLAIN <query>;\"")
    else:
        ok("Sin queries activas de más de 10 segundos")

    sub("THREADS EN TIEMPO REAL")
    threads = mysql_q("SHOW STATUS LIKE 'Threads_%';")
    if threads: w(threads)

    sub("VARIABLES CLAVE DE CONFIGURACIÓN")
    for var in ["innodb_buffer_pool_size","max_connections","slow_query_log",
                "slow_query_log_file","long_query_time","skip_name_resolve",
                "innodb_log_buffer_size","tmp_table_size","join_buffer_size",
                "sort_buffer_size","innodb_flush_log_at_trx_commit"]:
        val = mysql_q(f"SHOW VARIABLES LIKE '{var}';")
        if val:
            last = val.splitlines()[-1] if val else ""
            w(f"  {last}")

    sub("ESTADÍSTICAS DE RENDIMIENTO")
    for var in ["Innodb_buffer_pool_reads","Innodb_buffer_pool_read_requests",
                "Slow_queries","Questions","Aborted_connects","Table_locks_waited",
                "Max_used_connections","Created_tmp_disk_tables","Created_tmp_tables"]:
        val = mysql_q(f"SHOW STATUS LIKE '{var}';")
        if val:
            w(f"  {val.splitlines()[-1]}")

    # Eficiencia buffer pool
    sub("EFICIENCIA BUFFER POOL InnoDB")
    bp_r, _ = run("mysql --connect-timeout=5 -e \"SHOW STATUS LIKE 'Innodb_buffer_pool_reads';\" 2>/dev/null | awk 'NR==2{print $2}'")
    bp_rq, _ = run("mysql --connect-timeout=5 -e \"SHOW STATUS LIKE 'Innodb_buffer_pool_read_requests';\" 2>/dev/null | awk 'NR==2{print $2}'")
    try:
        reads = int(bp_r.strip())
        reqs  = int(bp_rq.strip())
        if reqs > 0:
            hit = round((1 - reads/reqs) * 100, 2)
            color = C.GREEN if hit >= 95 else C.RED
            w(f"  Hit rate: {color}{hit}%{C.RESET}  (ideal >= 95%)")
            if hit < 95:
                crit(f"Buffer pool ineficiente ({hit}%) — MySQL leyendo del disco")
                rec("Aumentar innodb_buffer_pool_size en /etc/my.cnf (cPanel) o /etc/mysql/mysql.conf.d/mysqld.cnf (Ubuntu/Ploi)")
            else:
                ok(f"Buffer pool eficiente ({hit}%)")
    except Exception:
        pass

    # Buffer pool vs datos
    sub("BUFFER POOL vs DATOS InnoDB")
    bp_size, _ = run("mysql --connect-timeout=5 -e \"SHOW VARIABLES LIKE 'innodb_buffer_pool_size';\" 2>/dev/null | awk 'NR==2{print $2}'")
    data_out = mysql_q("SELECT ROUND(SUM(data_length+index_length)/1024/1024) "
                       "FROM information_schema.tables WHERE engine='InnoDB';")
    try:
        bp_mb   = int(bp_size.strip()) // (1024*1024)
        data_mb = 0
        for line in data_out.splitlines():
            try: data_mb = int(float(line.strip())); break
            except: pass
        w(f"  Buffer pool configurado : {bp_mb} MB")
        w(f"  Datos InnoDB en disco   : {data_mb} MB")
        if bp_mb < data_mb:
            crit(f"Buffer pool ({bp_mb} MB) < datos InnoDB ({data_mb} MB) — lee disco constantemente")
            rec(f"Objetivo: innodb_buffer_pool_size cercano a {data_mb}M — PERO validar antes que la RAM libre lo permite (ver sección 2). No asignar más del ~50-60% de la RAM en un servidor compartido con PHP-FPM.")
        else:
            ok(f"Buffer pool ({bp_mb} MB) cubre los datos InnoDB ({data_mb} MB)")
    except Exception:
        pass

    # Tamaño bases de datos
    sub("TAMAÑO DE BASES DE DATOS")
    db_size = mysql_q("SELECT table_schema AS BD, "
                      "ROUND(SUM(data_length+index_length)/1024/1024,1) AS MB, "
                      "COUNT(*) AS Tablas "
                      "FROM information_schema.tables "
                      "WHERE table_type NOT LIKE '%view%' "
                      "GROUP BY table_schema ORDER BY 2 DESC;")
    if db_size: w(db_size)

    # Tablas MyISAM
    sub("TABLAS MyISAM (motor obsoleto — bloqueo tabla completa)")
    myisam_count_out = mysql_q("SELECT COUNT(*) FROM information_schema.tables "
                                "WHERE engine='MyISAM' AND table_schema NOT IN "
                                "('information_schema','mysql','performance_schema','sys');")
    myisam_count = 0
    for line in myisam_count_out.splitlines():
        try: myisam_count = int(line.strip()); break
        except: pass

    info(f"Tablas en MyISAM: {myisam_count}")
    if myisam_count > 0:
        warn(f"{myisam_count} tablas MyISAM — bloqueo a nivel de tabla completa en escrituras concurrentes")
        rec("Migrar a InnoDB elimina los bloqueos que generan load alto")

        top_myisam = mysql_q("SELECT table_schema, table_name, "
                              "ROUND((data_length+index_length)/1024/1024,2) AS MB "
                              "FROM information_schema.tables WHERE engine='MyISAM' "
                              "AND table_schema NOT IN ('information_schema','mysql','performance_schema','sys') "
                              "ORDER BY (data_length+index_length) DESC LIMIT 20;")
        if top_myisam: w(top_myisam)

        sql_cmds = mysql_q("SELECT CONCAT('ALTER TABLE \\`',table_schema,'\\`.\\`',table_name,'\\` ENGINE=InnoDB;') "
                            "FROM information_schema.tables WHERE engine='MyISAM' "
                            "AND table_schema NOT IN ('information_schema','mysql','performance_schema','sys') "
                            "ORDER BY table_schema, table_name;")
        if sql_cmds:
            with open(SQL_FILE, "w") as f:
                f.write("-- Linux Infra Audit Tool v1.0\n")
                f.write(f"-- Generado: {datetime.datetime.now()}\n")
                f.write("-- ⚠ EJECUTAR EN VENTANA DE MANTENIMIENTO\n")
                f.write("-- ⚠ SUPUESTOS: hay backup verificado y espacio libre en disco\n")
                f.write("--   >= 2x el tamaño de la tabla más grande (ALTER copia la tabla).\n")
                f.write("-- Backup: mysqldump --all-databases > /root/backup_pre_innodb.sql\n\n")
                f.write("SET foreign_key_checks = 0;\n\n")
                for line in sql_cmds.splitlines():
                    if "ALTER TABLE" in line:
                        f.write(line.strip() + "\n")
                f.write("\nSET foreign_key_checks = 1;\n")
            ok(f"Script migración guardado: {SQL_FILE}")
    else:
        ok("No hay tablas MyISAM en bases de datos de usuario")

    # Tablas sin índice primario
    sub("TABLAS SIN CLAVE PRIMARIA")
    no_pk = mysql_q("SELECT t.table_schema, t.table_name "
                    "FROM information_schema.tables t "
                    "LEFT JOIN information_schema.table_constraints c "
                    "ON t.table_schema=c.table_schema AND t.table_name=c.table_name "
                    "AND c.constraint_type='PRIMARY KEY' "
                    "WHERE c.table_name IS NULL AND t.table_type='BASE TABLE' "
                    "AND t.table_schema NOT IN ('information_schema','mysql','performance_schema','sys') "
                    "LIMIT 20;")
    if no_pk and "table_name" in no_pk:
        warn("Tablas sin clave primaria:")
        w(no_pk)
        rec("Agregar PRIMARY KEY mejora rendimiento de InnoDB y replicación")
    else:
        ok("Todas las tablas tienen clave primaria")

    # Joins sin índice
    sub("JOINS SIN ÍNDICE (acumulado desde inicio)")
    joins = mysql_q("SHOW STATUS LIKE 'Select_full_join';")
    if joins:
        w(joins)
        for line in joins.splitlines():
            p = line.split()
            if len(p) >= 2 and p[-1].isdigit() and int(p[-1]) > 1000:
                crit(f"Se han realizado {p[-1]} JOINs sin índice — causa de lentitud")
                rec("Activar slow log: SET GLOBAL slow_query_log=ON; SET GLOBAL long_query_time=2;")
                rec("La ruta del slow log la indica la variable slow_query_log_file (arriba)")

    # Deadlocks
    sub("DEADLOCKS RECIENTES")
    dl_out, _ = run("mysql --connect-timeout=5 -e \"SHOW ENGINE INNODB STATUS\\G\" 2>/dev/null | grep -A 20 'LATEST DETECTED DEADLOCK'")
    if "TRANSACTION" in (dl_out or ""):
        warn("Deadlock detectado:"); w(dl_out)
        rec("Revisar el orden de bloqueos en la aplicación")
    else:
        ok("Sin deadlocks recientes")

    # DB Governor (CloudLinux) — usuarios restringidos por consumo MySQL
    sub("DB GOVERNOR (CloudLinux) — USUARIOS RESTRINGIDOS")
    if os.path.exists("/var/log/dbgovernor-restrict.log"):
        restr, _ = run("tail -20 /var/log/dbgovernor-restrict.log 2>/dev/null")
        if restr:
            warn("DB Governor ha restringido usuarios por consumo MySQL (últimas 20 líneas):")
            w(restr)
            rec("Estos usuarios son candidatos principales de la saturación de MySQL")
            rec("Errores del governor: tail -30 /var/log/dbgovernor-error.log")
        else:
            ok("DB Governor presente, sin restricciones registradas")
    else:
        info("DB Governor no presente (normal si no es CloudLinux)")

    # MySQLTuner
    sub("MySQLTuner — Análisis completo")
    if has("perl"):
        if not os.path.exists(TUNER):
            info("Descargando MySQLTuner...")
            _, rc2 = run(f"curl -s {TUNER_URL} -o {TUNER} 2>/dev/null")
            if rc2 != 0:
                warn("No se pudo descargar MySQLTuner")
                rec(f"curl -o {TUNER} {TUNER_URL}")
        if os.path.exists(TUNER):
            info("Ejecutando MySQLTuner (puede tardar ~30s)...")
            tuner_out, _ = run(f"perl {TUNER} --nogood --nowarn 2>/dev/null", timeout=120)
            if tuner_out:
                w(tuner_out)
            else:
                warn("MySQLTuner no retornó resultados")
    else:
        warn("Perl no disponible — MySQLTuner no puede ejecutarse")
        rec("yum install perl || apt install perl")

    return myisam_count

# ============================================================
# 5. PHP-FPM
# ============================================================
def check_phpfpm(total_mb):
    sep("5. PHP-FPM — WORKERS Y POOLS")

    procs = read_procs()   # reutiliza el muestreo cacheado (no vuelve a dormir 1s)
    fpm_procs = [p for p in procs if "php-fpm" in p["cmd"].lower() or "php-fpm" in p["comm"].lower()]
    master_procs = [p for p in fpm_procs if "master" in p["cmd"].lower()]

    if not fpm_procs:
        info("PHP-FPM no detectado"); return

    ok(f"PHP-FPM activo ({len(fpm_procs)} procesos totales, {len(master_procs)} master)")

    sub("WORKERS ACTIVOS AHORA")
    workers = [p for p in fpm_procs if "master" not in p["cmd"].lower()]
    info(f"Workers activos: {len(workers)}")
    if workers:
        ram_vals = [p["rss_mb"] for p in workers]
        avg_mb   = sum(ram_vals) / max(len(ram_vals), 1)
        total_w  = sum(ram_vals)
        color    = C.RED if avg_mb > 150 else (C.YELLOW if avg_mb > 80 else C.GREEN)
        w(f"  RAM promedio/worker : {color}{avg_mb:.0f} MB{C.RESET}")
        w(f"  RAM total PHP-FPM   : {total_w:.0f} MB ({total_w/max(total_mb,1)*100:.1f}% del servidor)")
        if avg_mb > 150:
            warn(f"Workers PHP usan {avg_mb:.0f} MB en promedio")
            rec("Revisar memory_limit en php.ini — puede estar configurado demasiado alto")

        # Workers por usuario — qué cuenta tiene PHP saturado
        by_user = {}
        for p in workers:
            u = by_user.setdefault(p["user"], {"n": 0, "cpu": 0.0, "ram": 0.0})
            u["n"] += 1; u["cpu"] += p["cpu_pct"]; u["ram"] += p["rss_mb"]
        top = sorted(by_user.items(), key=lambda kv: kv[1]["cpu"], reverse=True)[:10]
        w(f"\n  {C.BOLD}{'USUARIO (cuenta)':<20} {'WORKERS':>8} {'CPU%':>8} {'RAM MB':>10}{C.RESET}")
        w(f"  {'─'*50}")
        for name, u in top:
            color = C.RED if u["cpu"] > 60 else (C.YELLOW if u["cpu"] > 30 else C.RESET)
            w(f"  {color}{name:<20} {u['n']:>8} {u['cpu']:>7.1f}% {u['ram']:>10.1f}{C.RESET}")

    # Pools cPanel
    if os.path.isdir("/opt/cpanel"):
        sub("POOLS PHP-FPM (cPanel) — TOP POR max_children")
        pools_raw, _ = run("grep -rH 'pm.max_children' /opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf 2>/dev/null | grep -v '.save:'")
        pool_data = []
        for line in (pools_raw or "").splitlines():
            if "=" in line:
                fp  = line.split(":")[0]
                val = line.split("=")[-1].strip()
                dom = os.path.basename(fp).replace(".conf","")
                if val.isdigit():
                    pool_data.append((int(val), dom, fp))
        pool_data.sort(reverse=True)

        w(f"\n  {C.BOLD}{'DOMINIO':<45} {'MAX_CHILDREN':>12}{C.RESET}")
        w(f"  {'─'*60}")
        for val, dom, fp in pool_data[:25]:
            color = C.RED if val > 30 else (C.YELLOW if val > 15 else C.GREEN)
            w(f"  {color}{dom:<45} {val:>12}{C.RESET}")
            if val > 50:
                crit(f"Pool {dom} con max_children={val} — excesivo")
                rec(f"Reducir a 10-20 vía WHM > MultiPHP Manager (los overrides viven en /var/cpanel/php-fpm/<usuario>/ — NO editar el .conf generado en /opt/cpanel, se sobreescribe)")

        total_possible = sum(v for v, _, _ in pool_data)
        est_ram = total_possible * 60
        info(f"\n  Max workers posibles (suma): {total_possible}")
        info(f"  RAM estimada al máximo: {est_ram} MB de {total_mb} MB (supuesto: ~60 MB/worker — validar contra el promedio real medido arriba)")
        if est_ram > total_mb * 0.7:
            warn(f"Pools podrían consumir hasta {est_ram} MB — mayor que el 70% de la RAM")
            rec("Reducir max_children en pools inactivos, demo, prueba, old a 3-5")

        # Slow logs PHP-FPM por usuario — identifica el script que satura
        sub("SLOW LOGS PHP-FPM POR USUARIO (/var/cpanel/php-fpm/*/logs/slow.log)")
        slow_logs, _ = run("find /var/cpanel/php-fpm -maxdepth 3 -name 'slow.log' -size +0c 2>/dev/null | head -10")
        if slow_logs:
            warn("Usuarios con entradas en slow.log de PHP-FPM (scripts lentos):")
            for lf in slow_logs.splitlines():
                user_name = lf.split("/")[4] if len(lf.split("/")) > 4 else lf
                cnt, _ = run(f"grep -c 'pool ' {lf} 2>/dev/null")
                w(f"  {C.YELLOW}{user_name:<25} entradas: {(cnt or '?').strip():<8} {lf}{C.RESET}")
                last_e, _ = run(f"grep 'script_filename' {lf} 2>/dev/null | tail -3")
                if last_e:
                    w(f"{last_e}")
            rec("Los scripts listados son los que exceden request_slowlog_timeout — revisar con el cliente o cachear")
        else:
            ok("Sin slow logs PHP-FPM con contenido (o request_slowlog_timeout no configurado)")
    else:
        # Non-cPanel (Ubuntu/Ploi: un pool por sitio en pool.d/)
        sub("CONFIGURACIÓN PHP-FPM")
        pool_files = glob.glob("/etc/php/*/fpm/pool.d/*.conf") + glob.glob("/etc/php-fpm.d/*.conf")
        for conf in pool_files[:30]:
            if os.path.exists(conf):
                info(f"Pool: {conf}")
                pm_out, _ = run(f"grep '^pm' {conf}")
                w(pm_out)
                m = re.search(r"pm\.max_children\s*=\s*(\d+)", pm_out or "")
                if m:
                    max_ch  = int(m.group(1))
                    est_ram = max_ch * 60
                    info(f"RAM estimada máxima: ~{est_ram} MB ({max_ch} × 60 MB — supuesto, validar con uso real)")
                    if est_ram > total_mb * 0.7:
                        crit(f"pm.max_children={max_ch} puede consumir {est_ram} MB de {total_mb} MB")
                        safe = max(5, total_mb * 50 // 100 // 60)
                        rec(f"Valor sugerido ~{safe} (editar {conf} y systemctl reload de la versión FPM — NO usar sed sin backup previo del archivo)")

    sub("PHP.ini — CONFIGURACIÓN CRÍTICA")
    php_bin = shutil.which("php") or shutil.which("php74") or shutil.which("php81")
    if php_bin:
        php_vars, _ = run(f"{php_bin} -r \"echo ini_get('memory_limit').'|'.ini_get('max_execution_time').'|'.ini_get('upload_max_filesize').'|'.ini_get('post_max_size').'|'.(extension_loaded('Zend OPcache') && ini_get('opcache.enable') ? '1' : '0');\" 2>/dev/null")
        if php_vars:
            parts  = php_vars.split("|")
            labels = ["memory_limit","max_execution_time","upload_max_filesize","post_max_size","opcache"]
            info("NOTA: valores del PHP CLI — el FPM de cada versión/pool puede diferir")
            for i, label in enumerate(labels):
                val = parts[i] if i < len(parts) else "N/A"
                info(f"  {label:<25}: {val}")
                if label == "memory_limit":
                    digits = re.sub(r"[^0-9]", "", val)
                    if digits.isdigit() and int(digits) >= 2048:
                        warn(f"memory_limit muy alto ({val}) — cada worker puede usar hasta {val}")
                        rec("Reducir a 256M-512M según uso real de la aplicación")
                if label == "max_execution_time" and val.isdigit() and int(val) >= 1800:
                    warn(f"max_execution_time muy alto ({val}s)")
                    rec("Reducir a 120-300 segundos")
                if label == "opcache" and val == "0":
                    warn("OPcache no activo en CLI (verificar también en FPM: php-fpm -i | grep opcache)")
                    rec("Activar en php.ini: opcache.enable=1  (reduce CPU notablemente)")
                elif label == "opcache":
                    ok("OPcache activo (CLI)")
    else:
        info("PHP CLI no disponible en PATH")

# ============================================================
# 6. SERVIDOR WEB
# ============================================================
def check_webserver():
    sep("6. SERVIDOR WEB (Apache / Nginx)")

    apache = shutil.which("httpd") or shutil.which("apache2")
    if apache:
        ok(f"Apache: {apache}")
        procs = read_procs()
        aw = [p for p in procs if "httpd" in p["cmd"] or "apache2" in p["cmd"]]
        info(f"Workers activos: {len(aw)}")
        if aw:
            total_ram = sum(p["rss_mb"] for p in aw)
            info(f"RAM total Apache: {total_ram:.0f} MB")

        test, rc = run(f"{apache} -t 2>&1")
        w(test)
        if rc != 0:
            crit("Errores en configuración Apache")
            rec(f"{apache} -t")

        max_req, _ = run("grep -r 'MaxRequestWorkers\\|MaxClients' /etc/apache2/ /usr/local/apache/conf/ 2>/dev/null | grep -v '#' | head -5")
        if max_req:
            w(max_req)
            for line in max_req.splitlines():
                m = re.search(r"(\d+)", line)
                if m and int(m.group(1)) > 100:
                    warn(f"MaxRequestWorkers alto ({m.group(1)})")
                    rec("Reducir a 50-80 para servidores < 8 GB RAM (vía WHM > Apache Configuration — /etc/apache2/conf/httpd.conf lo genera cPanel, no editar a mano)")
        else:
            warn("MaxRequestWorkers no configurado (default 150)")
            rec("Configurar en WHM > Apache Configuration")

        # Errores recientes de Apache — señal de saturación de workers
        err_log = "/var/log/apache2/error_log"
        if os.path.exists(err_log):
            maxc, _ = run(f"grep -c 'MaxRequestWorkers' {err_log} 2>/dev/null")
            if (maxc or "").strip().isdigit() and int(maxc.strip()) > 0:
                crit(f"Apache alcanzó MaxRequestWorkers {maxc.strip()} veces (error_log) — peticiones en cola")
                rec(f"Ver: grep 'MaxRequestWorkers' {err_log} | tail -5")

    if has("nginx"):
        ok("Nginx detectado")
        test, rc = run("nginx -t 2>&1")
        w(test)
        if rc != 0:
            crit("Errores en configuración Nginx")
        timeouts, _ = run("grep -r 'fastcgi_read_timeout\\|proxy_read_timeout' /etc/nginx/ 2>/dev/null | grep -v '#' | head -5")
        if timeouts:
            sub("TIMEOUTS NGINX"); w(timeouts)

    if not apache and not has("nginx"):
        info("No se detectó Apache ni Nginx")

# ============================================================
# 7. CORREO
# ============================================================
def check_mail():
    sep("7. CORREO (Exim / Dovecot)")

    if has("exim"):
        ok("Exim detectado")
        queue, _ = run("exim -bpc 2>/dev/null")
        count = int(queue.strip()) if (queue or "").strip().isdigit() else 0
        color = C.RED if count > 500 else (C.YELLOW if count > 100 else C.GREEN)
        w(f"  Cola de correo: {color}{count} mensajes{C.RESET}")
        if count > 500:
            crit(f"Cola crítica: {count} mensajes")
            rec("exim -bp | grep '<' | awk '{print $4}' | sort | uniq -c | sort -rn | head -10")
        elif count > 100:
            warn(f"Cola elevada: {count} mensajes")
        else:
            ok(f"Cola normal ({count})")

        if count > 0:
            senders, _ = run("exim -bp 2>/dev/null | grep '<' | awk '{print $4}' | sort | uniq -c | sort -rn | head -10")
            if senders:
                sub("TOP REMITENTES EN COLA"); w(senders)
    else:
        info("Exim no detectado")

    if has("doveadm"):
        ok("Dovecot detectado")
        sub("BUZONES PESADOS (> 5000 correos en inbox)")
        info("NOTA: en servidores con 300+ cuentas este find puede ser lento")
        heavy = False
        dirs, _ = run("find /home/*/mail -maxdepth 2 -name 'cur' -type d 2>/dev/null | head -50", timeout=60)
        for d in (dirs or "").splitlines():
            cnt, _ = run(f"ls {d} 2>/dev/null | wc -l")
            if (cnt or "").strip().isdigit() and int(cnt.strip()) > 5000:
                heavy = True
                warn(f"Buzón con {cnt.strip()} correos: {d}")
                rec(f"doveadm force-resync -u USER INBOX  (para reindexar)")
        if not heavy:
            ok("Sin buzones con más de 5000 correos (en los primeros 50 revisados)")
    else:
        info("Dovecot no detectado")

# ============================================================
# 8. CLOUDLINUX LVE — límites por cuenta (si aplica)
# ============================================================
def check_cloudlinux():
    sep("8. CLOUDLINUX LVE (límites por cuenta)")

    if not has("lvectl"):
        info("CloudLinux/LVE no presente en este servidor")
        return

    ok("CloudLinux LVE detectado")
    sub("LVE ACTIVOS (lvectl list — usuarios con límites en uso)")
    lve, _ = run("lvectl list 2>/dev/null | head -40")
    w(lve or "  (sin salida)")

    # Usuarios que ESTÁN tocando sus límites ahora
    sub("USUARIOS EN FALLO DE LÍMITE (lveinfo si disponible)")
    if has("lveinfo"):
        faults, _ = run("lveinfo --period=1h --by-fault=any --limit=10 2>/dev/null", timeout=60)
        if faults and len(faults.splitlines()) > 3:
            warn("Usuarios que alcanzaron límites LVE en la última hora:")
            w(faults)
            rec("Estas cuentas son los candidatos directos de la saturación")
        else:
            ok("Sin usuarios en fault LVE en la última hora")
    else:
        info("lveinfo no disponible — usar: lvectl list y /var/log/lve-stats.log")

# ============================================================
# 9. SEGURIDAD
# ============================================================
def check_security():
    sep("9. SEGURIDAD")

    sub("ÚLTIMOS ACCESOS")
    last, _ = run("last 2>/dev/null | head -15")
    w(last or "  (sin datos)")

    sub("IPs CON INTENTOS FALLIDOS SSH")
    failed, _ = run("grep 'Failed password' /var/log/secure /var/log/auth.log 2>/dev/null | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -10")
    if failed:
        w(failed)
        for line in failed.splitlines():
            p = line.strip().split()
            if len(p) >= 2 and p[0].isdigit() and int(p[0]) > 100:
                crit(f"IP {p[1]} con {p[0]} intentos fallidos SSH")
                rec(f"Verificar que no sea una IP legítima (revisar /etc/csf/csf.allow) y bloquear: csf -d {p[1]}")
    else:
        ok("Sin intentos fallidos SSH en logs disponibles")

    sub("PUERTOS EN ESCUCHA")
    ports, _ = run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    w(ports or "  (sin datos)")

    sub("USUARIOS CON UID 0")
    uid0, _ = run("awk -F: '$3==0{print $1}' /etc/passwd 2>/dev/null")
    w(uid0 or "  root")
    uid_list = [u.strip() for u in (uid0 or "").splitlines() if u.strip()]
    if len(uid_list) > 1:
        crit(f"Múltiples usuarios con UID 0: {', '.join(uid_list)}")
    else:
        ok("Solo root con UID 0")

    sub("FIREWALL")
    if has("csf"):
        ok("CSF Firewall instalado")
        # Verificar que no esté en TESTING mode (común tras instalar)
        testing, _ = run("grep -E '^TESTING\\s*=' /etc/csf/csf.conf 2>/dev/null")
        if '"1"' in (testing or ""):
            crit("CSF está en modo TESTING — el firewall NO está aplicando bloqueos permanentes")
            rec("Editar /etc/csf/csf.conf: TESTING=\"0\" y reiniciar: csf -r")
        rules, _ = run("csf -l 2>/dev/null | wc -l")
        info(f"Reglas activas: {(rules or '?').strip()}")
    elif has("ufw"):
        st, _ = run("ufw status 2>/dev/null")
        ok("UFW activo") if "active" in (st or "").lower() else warn("UFW instalado pero no activo")
    else:
        warn("No se detectó firewall (CSF/UFW)")
        rec("Instalar CSF: https://configserver.com/cp/csf.html")

    sub("SEGURIDAD MySQL")
    if has("mysql"):
        test, rc = run("mysqladmin --connect-timeout=3 status 2>/dev/null", timeout=5)
        if rc == 0:
            no_pass, _ = run("mysql --connect-timeout=3 -e \"SELECT user,host FROM mysql.user WHERE (authentication_string='' OR authentication_string IS NULL) AND user!='';\" 2>/dev/null")
            if no_pass and "user" in no_pass:
                warn("Usuarios MySQL sin contraseña:"); w(no_pass)
            else:
                ok("Todos los usuarios MySQL con contraseña")

    sub("HERRAMIENTAS")
    for path, name in [("/opt/imunify360","Imunify360"), ("/var/ossec","Wazuh/OSSEC")]:
        if os.path.isdir(path):
            ok(f"{name} instalado")
        else:
            info(f"{name} no instalado")

# ============================================================
# 10. SERVICIOS
# ============================================================
def check_services():
    sep("10. ESTADO DE SERVICIOS CRÍTICOS")

    services = [
        "mysql","mysqld","mariadb",
        "httpd","apache2","nginx",
        "php-fpm","php7.4-fpm","php8.0-fpm","php8.1-fpm","php8.2-fpm","php8.3-fpm","php8.4-fpm",
        "exim","dovecot","postfix",
        "csf","lfd","wazuh-agent","redis","redis-server",
        "memcached","cron","crond","fail2ban","imunify360",
        "jetbackup5d","jetmongod","cpanel-dovecot-solr",
    ]

    w(f"\n  {C.BOLD}{'SERVICIO':<25} {'HABILITADO':>12} {'ESTADO':>12}{C.RESET}")
    w(f"  {'─'*52}")
    for svc in services:
        enabled, rc1 = run(f"systemctl is-enabled {svc} 2>/dev/null")
        if rc1 == 0 and (enabled or "").strip() in ("enabled","static","indirect"):
            status, _ = run(f"systemctl is-active {svc} 2>/dev/null")
            status = (status or "unknown").strip()
            color  = C.GREEN if status == "active" else C.RED
            w(f"  {svc:<25} {'enabled':>12} {color}{status:>12}{C.RESET}")
            if status != "active":
                crit(f"Servicio {svc} habilitado pero no activo")
                rec(f"Diagnosticar ANTES de reiniciar: systemctl status {svc} && journalctl -u {svc} -n 30")

# ============================================================
# 11. LOGS
# ============================================================
def check_logs():
    sep("11. LOGS Y ERRORES RECIENTES")

    sub("ERRORES DEL SISTEMA (últimas 24h)")
    journal, _ = run("journalctl --since '24 hours ago' -p err --no-pager 2>/dev/null | tail -20")
    w(journal or "  journalctl sin errores críticos recientes")

    sub("ERRORES MySQL")
    # /var/log/mysqld.log = MySQL 8 cPanel/AlmaLinux; /var/log/mysql/error.log = Ubuntu/Ploi
    for log in ["/var/log/mysqld.log","/var/log/mysql/error.log"]:
        if os.path.exists(log) and os.path.getsize(log) > 0:
            info(f"Log: {log}")
            errors, _ = run(f"grep -i 'error\\|warning\\|crash' {log} 2>/dev/null | grep -v 'Note' | tail -10")
            w(errors or "  Sin errores recientes")

    sub("ERRORES PHP-FPM POR VERSIÓN (EA4)")
    fpm_logs, _ = run("ls /opt/cpanel/ea-php*/root/usr/var/log/php-fpm/error.log 2>/dev/null")
    if fpm_logs:
        for lf in fpm_logs.splitlines()[:10]:
            e, _ = run(f"grep -iE 'max_children|error|warning' {lf} 2>/dev/null | tail -3")
            if e and "max_children" in e:
                crit(f"Pool alcanzó max_children en {lf}:")
                w(f"{C.RED}{e}{C.RESET}")
                rec("El pool se queda sin workers — subir max_children de ESE pool o arreglar el script lento")
            elif e:
                w(f"  {lf}:"); w(e)
    else:
        info("Sin logs PHP-FPM EA4 (normal si no es cPanel)")

    sub("ERRORES PHP por usuario")
    php_logs, _ = run("find /home/*/logs -maxdepth 1 -name '*.error.log' -size +0c 2>/dev/null | head -5", timeout=60)
    if php_logs:
        for lf in php_logs.splitlines():
            if os.path.exists(lf):
                e, _ = run(f"grep -i 'fatal\\|parse error' {lf} 2>/dev/null | tail -3")
                if e:
                    warn(f"Errores PHP en {lf}:"); w(e)
    else:
        ok("Sin errores PHP recientes encontrados")

    sub("MENSAJES DEL SISTEMA (últimas líneas)")
    syslog, _ = run("tail -20 /var/log/messages /var/log/syslog 2>/dev/null | tail -20")
    if syslog:
        w(syslog)

# ============================================================
# 12. RESUMEN EJECUTIVO
# ============================================================
def print_summary():
    sep("12. RESUMEN EJECUTIVO")

    score = max(0, 100 - len(FINDINGS["critical"]) * 15 - len(FINDINGS["warning"]) * 5)
    cs    = C.GREEN if score >= 80 else (C.YELLOW if score >= 60 else C.RED)
    w(f"\n  {C.BOLD}PUNTUACIÓN DE SALUD: {cs}{score}/100{C.RESET}")
    w(f"  {C.RED}Críticos: {len(FINDINGS['critical'])}{C.RESET}  |  "
      f"{C.YELLOW}Advertencias: {len(FINDINGS['warning'])}{C.RESET}  |  "
      f"{C.GREEN}OK: {len(FINDINGS['ok'])}{C.RESET}")

    if FINDINGS["critical"]:
        w(f"\n{C.RED}{'═'*62}\n  ✘ CRÍTICOS — Acción inmediata ({len(FINDINGS['critical'])})\n{'═'*62}{C.RESET}")
        for i, m in enumerate(FINDINGS["critical"], 1):
            w(f"{C.RED}  {i:02d}. {m}{C.RESET}")

    if FINDINGS["warning"]:
        w(f"\n{C.YELLOW}{'═'*62}\n  ⚠ ADVERTENCIAS ({len(FINDINGS['warning'])})\n{'═'*62}{C.RESET}")
        for i, m in enumerate(FINDINGS["warning"], 1):
            w(f"{C.YELLOW}  {i:02d}. {m}{C.RESET}")

    if FINDINGS["rec"]:
        w(f"\n{C.CYAN}{'═'*62}\n  → RECOMENDACIONES ({len(FINDINGS['rec'])})\n{'═'*62}{C.RESET}")
        for i, m in enumerate(FINDINGS["rec"], 1):
            w(f"{C.CYAN}  {i:02d}. {m}{C.RESET}")

    if FINDINGS["ok"]:
        w(f"\n{C.GREEN}{'═'*62}\n  ✔ VERIFICACIONES CORRECTAS ({len(FINDINGS['ok'])})\n{'═'*62}{C.RESET}")
        for m in FINDINGS["ok"]:
            w(f"{C.GREEN}  ✔  {m}{C.RESET}")

    w(f"\n{C.BOLD}  NOTA DE LECTURA:{C.RESET}")
    w("  Las métricas de CPU son una ventana de 1 segundo — si el pico")
    w("  ya pasó, ejecutar de nuevo DURANTE el evento de saturación.")
    w("  Las recomendaciones son puntos de partida, no valores finales:")
    w("  validar cada cambio contra la RAM/CPU real del servidor antes")
    w("  de aplicar, y registrar los cambios finales en el changelog.")

# ============================================================
# FOOTER
# ============================================================
def footer():
    now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    w(f"\n{'═'*62}\n  ARCHIVOS GENERADOS\n{'═'*62}")
    w(f"  Reporte      : {OUT_FILE}")
    if os.path.exists(SQL_FILE):
        w(f"  Script MySQL : {SQL_FILE}")
    w(f"\n  FILTROS RÁPIDOS:")
    w(f"  Críticos     : grep '✘' {OUT_FILE}")
    w(f"  Advertencias : grep '⚠' {OUT_FILE}")
    w(f"  Recomendac.  : grep '→' {OUT_FILE}")
    w(f"  Completo     : cat {OUT_FILE} | less")
    if os.path.exists(SQL_FILE):
        w(f"\n  MIGRACIÓN MyISAM→InnoDB (ventana de mantenimiento):")
        w(f"  1) Backup   : mysqldump --all-databases > /root/backup_pre_innodb.sql")
        w(f"  2) Verificar: espacio libre >= 2x la tabla MyISAM más grande")
        w(f"  3) Ejecutar : mysql < {SQL_FILE}")
    w(f"\n  Completado: {now}\n{'═'*62}\n")

# ============================================================
# MAIN
# ============================================================
def main():
    if os.geteuid() != 0:
        print(f"{C.RED}Error: ejecutar como root{C.RESET}")
        print("Uso: sudo python3 infra_audit.py")
        sys.exit(1)

    header()
    check_top_consumers()             # 1. Qué consume recursos AHORA
    sys_info = check_resources()      # 2. RAM / Swap / CPU / I/O
    check_disk()                      # 3. Disco + inodos
    check_mysql()                     # 4. MySQL completo + DB Governor
    check_phpfpm(sys_info["total_mb"])# 5. PHP-FPM + slow logs por usuario
    check_webserver()                 # 6. Apache / Nginx
    check_mail()                      # 7. Correo
    check_cloudlinux()                # 8. CloudLinux LVE
    check_security()                  # 9. Seguridad
    check_services()                  # 10. Servicios
    check_logs()                      # 11. Logs
    print_summary()                   # 12. Resumen
    footer()
    save()
    print(f"\n{C.GREEN}  Reporte guardado: {OUT_FILE}{C.RESET}\n")

if __name__ == "__main__":
    main()
