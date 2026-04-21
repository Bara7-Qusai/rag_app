import json
import re
from typing import List, Any
from datetime import datetime


# ======= SCHEMA DETECTOR =======

def detect_schema(data: Any) -> str:

    if isinstance(data, dict) and "alerts" in data and isinstance(data["alerts"], list):
        alerts = data["alerts"]
        if not alerts:
            return "generic_alerts"
        first = alerts[0]
        keys = set(first.keys())
        if {"rule", "agent", "manager"}.issubset(keys):
            return "wazuh"
        if {"id", "timestamp", "event_type", "severity"}.issubset(keys):
            return "generic_alerts"
        return "generic_alerts"

    if isinstance(data, list) and len(data) > 0:
        first = data[0]
    elif isinstance(data, dict):
        first = data
    else:
        return "unknown"

    keys = set(first.keys())

    if {"rule", "agent", "manager"}.issubset(keys):
        return "wazuh"
    if "caseId" in keys or first.get("_type") in ("case", "alert"):
        return "thehive"
    if {"event_type", "src_ip", "dest_ip"}.issubset(keys):
        return "suricata"
    if {"_source", "_index"}.issubset(keys):
        return "elastic"
    if "hits" in keys and isinstance(first.get("hits"), dict) and "hits" in first["hits"]:
        return "elastic_search"

    return "unknown"


# ======= LOADERS =======

def load_json_file(file_path: str) -> tuple:
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read().strip()

    if content.startswith("[") or content.startswith("{"):
        try:
            data = json.loads(content)
            return data, detect_schema(data)
        except json.JSONDecodeError:
            pass

    # NDJSON fallback
    records = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return records, detect_schema(records)


# ======= WAZUH HELPERS =======

_RULE_ATTACK_MAP = {
    "5501": "authentication", "5502": "authentication", "5503": "authentication",
    "5551": "brute_force",
    "5710": "brute_force", "5711": "brute_force", "5712": "brute_force",
    "5716": "brute_force", "5720": "brute_force", "5760": "brute_force",
    "5715": "authentication_success",
    "5540": "account_compromise", "5550": "account_compromise",
    "5402": "privilege_escalation", "5403": "privilege_escalation",
    "5404": "privilege_escalation",
    # FIX 1: rootcheck rules -> "rootkit" (was "malware") — maps cleanly to T1014
    "510": "rootkit", "511": "rootkit", "512": "rootkit",
    "533": "network_change",
    "550": "file_integrity", "554": "file_integrity",
    "81101": "removable_media", "81102": "removable_media",
    "4151": "network_anomaly", "4152": "network_anomaly",
    "20101": "network_anomaly", "20151": "network_anomaly",
    "80730": "defense_evasion", "80731": "defense_evasion",
    "80781": "defense_evasion",
    "31100": "web_attack", "31101": "web_attack", "31151": "web_attack",
    "23001": "vulnerability", "23002": "vulnerability",
    "502": "system_change", "5901": "system_change", "5902": "system_change",
}

# FIX 2: Static MITRE injection table.
# Wazuh rootcheck rules (510-512) ship WITHOUT rule.mitre populated.
# This table injects correct MITRE IDs so LLM always sees accurate mappings.
_RULE_MITRE_INJECT = {
    "510":  ["T1014"],
    "511":  ["T1014"],
    "512":  ["T1014"],
    "533":  [],
    "5402": ["T1548.003"],
    "5403": ["T1548.003"],
    "5404": ["T1548.003"],
    "5501": ["T1078"],
    "5502": ["T1078"],
    "5715": ["T1078", "T1021"],
    "5710": ["T1110"],
    "5711": ["T1110"],
    "5716": ["T1110"],
    "5551": ["T1110"],
    "5540": ["T1078"],
    "550":  ["T1565.001"],
    "554":  ["T1565.001"],
}

_MITRE_TACTIC_MAP = {
    "T1014":     ["Defense Evasion"],
    "T1078":     ["Defense Evasion", "Persistence", "Privilege Escalation", "Initial Access"],
    "T1021":     ["Lateral Movement"],
    "T1110":     ["Credential Access"],
    "T1548.003": ["Privilege Escalation", "Defense Evasion"],
    "T1565.001": ["Impact"],
}

_LOG_ATTACK_PATTERNS = [
    ("brute_force",          ["failed password", "authentication failure", "failed login",
                              "invalid user", "failed publickey"]),
    ("privilege_escalation", ["sudo:", "su:", "privilege escalation", "sudoers",
                              "pkexec", "setuid", "setgid"]),
    # FIX: trojaned is an INDICATOR, not confirmation - use file_tampering
    ("file_tampering",       ["trojan", "trojaned", "integrity check", "file changed"]),  # Was "rootkit"
    ("rootkit",              ["rootkit signature", "confirmed rootkit"]),  # Only for confirmed rootkit
    ("malware",              ["malware", "ransomware", "c2 connection", "command and control"]),
    # FIX: selinux alone is NOT defense evasion - requires clear evasion intent
    ("defense_evasion",      ["avc:", "ptrace", "ld_preload", "disable logging", "clear logs"]),  # Removed selinux/apparmor
    ("lateral_movement",     ["psexec", "wmiexec", "winrm", "ssh lateral", "pass-the-hash",
                              "pass-the-ticket", "mimikatz"]),
    ("exfiltration",         ["data exfil", "large upload", "dns tunnel", "icmp tunnel"]),
    ("web_attack",           ["sql injection", "xss", "path traversal", "../", "cmd.exe",
                              "/etc/passwd", "union select"]),
    ("network_anomaly",      ["port scan", "nmap", "masscan", "connection refused"]),
    ("account_compromise",   ["accepted password", "session opened for user root", "new session"]),
    # FIX: Add system_activity for non-malicious system events
    ("system_activity",      ["selinux:", "apparmor", "netstat", "iptables", "firewall"]),
]

_RE_TROJANED = re.compile(r"Trojaned version of file '([^']+)'")
_RE_FILEPATH  = re.compile(r"(?:file|path|binary)\s*['\"]?(/[^\s'\"]+)", re.IGNORECASE)


def _classify_attack(rule_id: str, full_log: str = "") -> str:
    if rule_id in _RULE_ATTACK_MAP:
        return _RULE_ATTACK_MAP[rule_id]
    log_lower = full_log.lower()
    for attack_type, patterns in _LOG_ATTACK_PATTERNS:
        if any(p in log_lower for p in patterns):
            return attack_type
    return "other"


def _inject_mitre(rule_id: str, existing_ids: list, existing_tactics: list,
                  existing_techniques: list) -> tuple:
    injected_ids = _RULE_MITRE_INJECT.get(rule_id, [])
    merged_ids   = list(dict.fromkeys(list(existing_ids) + injected_ids))

    merged_tactics = list(existing_tactics)
    for mid in injected_ids:
        for tactic in _MITRE_TACTIC_MAP.get(mid, []):
            if tactic not in merged_tactics:
                merged_tactics.append(tactic)

    return merged_ids, merged_tactics, list(existing_techniques)


def _parse_time(ts):
    if not ts:
        return None
    try:
        if isinstance(ts, (int, float)):
            return datetime.fromtimestamp(float(ts))
        ts_str = str(ts)
        if ts_str.endswith("Z"):
            ts_str = ts_str.replace("Z", "+00:00")
        return datetime.fromisoformat(ts_str)
    except Exception:
        return None


def _time_bucket(ts, window_sec: int = 600) -> int:
    dt = _parse_time(ts)
    if not dt:
        return 0
    return int(dt.timestamp() // window_sec)


def _get_severity_level(alert: dict) -> int:
    rule = alert.get("rule", {}) or {}
    level = rule.get("level")
    try:
        return int(level) if level is not None else 0
    except (ValueError, TypeError):
        return 0


def _extract_file_paths(full_log: str) -> list:
    paths = []
    for m in _RE_TROJANED.finditer(full_log):
        paths.append(m.group(1))
    if not paths:
        for m in _RE_FILEPATH.finditer(full_log):
            p = m.group(1)
            if len(p) > 3 and not p.startswith("/proc"):
                paths.append(p)
    return list(dict.fromkeys(paths))


def _normalize_wazuh_event(alert: dict) -> dict:
    data     = alert.get("data", {}) or {}
    agent    = alert.get("agent", {}) or {}
    rule     = alert.get("rule", {}) or {}
    full_log = alert.get("full_log", "") or ""

    # FIX 3: srcuser = the actor who ran the command (wazuh-user)
    # dstuser = the target/escalated-to user (root)
    # Old code mixed them, grouping wazuh-user+root events under "root"
    srcuser = data.get("srcuser") or ""
    dstuser = data.get("dstuser") or ""
    user    = srcuser or data.get("user") or ""

    # FIX 4: src_ip from data only — NOT from agent.ip
    # agent.ip = Wazuh management IP, not attacker IP
    # Mixing them caused 10.200.200.20 to appear on rootcheck (kali-vm) incorrectly
    src_ip = data.get("srcip") or data.get("src_ip") or ""
    dst_ip = data.get("dstip")  or data.get("dst_ip") or ""

    command    = data.get("command") or ""
    timestamp  = alert.get("timestamp") or ""
    rule_id    = str(rule.get("id", ""))
    rule_level = _get_severity_level(alert)
    attack_type = _classify_attack(rule_id, full_log)

    mitre_raw      = rule.get("mitre") or {}
    mitre_ids_raw  = mitre_raw.get("id", [])        if isinstance(mitre_raw, dict) else []
    mitre_tact_raw = mitre_raw.get("tactic", [])    if isinstance(mitre_raw, dict) else []
    mitre_tech_raw = mitre_raw.get("technique", []) if isinstance(mitre_raw, dict) else []

    # Merge rule.mitre with injection table (fixes missing MITRE on rootcheck)
    mitre_ids, mitre_tactics, mitre_techniques = _inject_mitre(
        rule_id, mitre_ids_raw, mitre_tact_raw, mitre_tech_raw
    )

    file_paths = _extract_file_paths(full_log)

    return {
        "agent":            agent.get("name", "unknown"),
        "srcuser":          srcuser,
        "dstuser":          dstuser,
        "user":             user,
        "src_ip":           src_ip,
        "dst_ip":           dst_ip,
        "command":          command,
        "file_paths":       file_paths,
        "timestamp":        timestamp,
        "timestamp_obj":    _parse_time(timestamp),
        "rule_id":          rule_id,
        "rule_description": rule.get("description", ""),
        "rule_groups":      rule.get("groups", []) or [],
        "rule_level":       rule_level,
        "attack_type":      attack_type,
        "mitre_ids":        mitre_ids,
        "mitre_tactics":    mitre_tactics,
        "mitre_techniques": mitre_techniques,
        "full_log":         full_log,
    }


# ======= CHUNKERS =======

_MAX_EVIDENCE_LINES = 5


def chunk_wazuh(records: List[dict]) -> List[dict]:
    from collections import defaultdict

    if isinstance(records, dict) and "alerts" in records:
        records = records["alerts"]

    groups = defaultdict(list)

    for alert in records:
        n = _normalize_wazuh_event(alert)

        # FIX 3 (continued): group key uses srcuser (actor) not dstuser (target)
        # rootcheck: no meaningful user — group by agent only, wider 1-hour window
        is_rootcheck = (
            "rootcheck" in n["rule_groups"]
            or alert.get("location", "") == "rootcheck"
        )

        window_sec = 3600 if is_rootcheck else 600
        actor  = "" if is_rootcheck else (n["srcuser"] or n["user"] or "_")
        src_ip = n["src_ip"] or "_"

        key = (
            n["agent"],
            actor or "_",
            src_ip,
            _time_bucket(n["timestamp"], window_sec=window_sec),
        )
        groups[key].append((n["timestamp_obj"], alert, n))

    chunks = []
    for incident_index, (key, items) in enumerate(groups.items(), start=1):
        items.sort(key=lambda x: x[0] or datetime.min)

        agent, actor, src_ip, _ = key

        severity_levels   = []
        rule_ids          = set()
        rule_descriptions = set()
        mitre_ids         = set()
        mitre_tactics     = set()
        mitre_techniques  = set()
        commands          = set()
        file_paths        = set()
        timestamps        = []
        attack_types      = set()
        evidence_lines    = []
        srcusers          = set()
        dstusers          = set()

        for _, _, n in items:
            if n["rule_id"]:
                rule_ids.add(n["rule_id"])
            if n["rule_description"]:
                rule_descriptions.add(n["rule_description"])
            if n["command"]:
                commands.add(n["command"])
            if n["srcuser"]:
                srcusers.add(n["srcuser"])
            if n["dstuser"]:
                dstusers.add(n["dstuser"])
            file_paths.update(n["file_paths"])
            severity_levels.append(n["rule_level"])
            mitre_ids.update(n["mitre_ids"])
            mitre_tactics.update(n["mitre_tactics"])
            mitre_techniques.update(n["mitre_techniques"])
            attack_types.add(n["attack_type"])
            if n["timestamp_obj"]:
                timestamps.append(n["timestamp_obj"].strftime("%Y-%m-%d %H:%M:%S"))
            evidence_lines.append(
                f"{n['timestamp']} | {n['attack_type']} | rule={n['rule_id']}"
                f" | srcuser={n['srcuser'] or 'N/A'}"
                f" | dstuser={n['dstuser'] or 'N/A'}"
                f" | src={n['src_ip'] or 'N/A'}"
                f" | dst={n['dst_ip'] or 'N/A'}"
                f" | cmd={n['command'] or 'N/A'}"
                f" | {n['rule_description'][:80]}"
            )

        event_count = len(items)
        max_level   = max(severity_levels) if severity_levels else 0

        corr = min(10, (
            min(event_count, 5)
            + min(len(rule_ids), 3)
            + (1 if srcusers else 0)
            + (1 if src_ip != "_" else 0)
        ))

        dominant_attack = _dominant_attack(attack_types)

        lines = [
            f"[INCIDENT-{incident_index}]"
            f" agent={agent}"
            f" | user={', '.join(sorted(srcusers)) or actor or 'unknown'}"
            f" | src_ip={src_ip if src_ip != '_' else 'N/A'}"
            f" | dst_ip=N/A",

            f"[SUMMARY]"
            f" {event_count} events"
            f" | max_severity={max_level}"
            f" | attack_type={dominant_attack}"
            f" | correlation_strength={corr}/10",

            f"[RULES] {', '.join(sorted(rule_ids)) or 'unknown'}",

            f"[RULE_DESCRIPTIONS] {' | '.join(sorted(rule_descriptions))[:200]}",

            f"[MITRE]"
            f" tactics={', '.join(sorted(mitre_tactics)) or 'N/A'}"
            f" | techniques={', '.join(sorted(mitre_techniques)) or 'N/A'}"
            f" | ids={', '.join(sorted(mitre_ids)) or 'N/A'}",
        ]

        if commands:
            lines.append(f"[COMMANDS] {', '.join(sorted(commands))[:200]}")

        # FIX 2 (continued): trojaned file paths as explicit IOC evidence
        if file_paths:
            lines.append(f"[FILE_PATHS] {', '.join(sorted(file_paths))[:300]}")

        lines.append(f"[EVIDENCE — top {min(_MAX_EVIDENCE_LINES, event_count)} of {event_count}]")
        lines.extend(evidence_lines[:_MAX_EVIDENCE_LINES])

        chunks.append({
            "text": "\n".join(lines),
            "metadata": {
                "source":               "wazuh",
                "incident_id":          f"INC-{incident_index:03d}",
                "agent":                agent,
                "user":                 ", ".join(sorted(srcusers)) or actor or "",
                "srcusers":             sorted(srcusers),
                "dstusers":             sorted(dstusers),
                "src_ip":               src_ip if src_ip != "_" else "",
                "dst_ip":               "",
                "attack_type":          dominant_attack,
                "rule_id":              ",".join(sorted(rule_ids)),
                "severity":             ",".join(str(x) for x in sorted(set(severity_levels))),
                "max_level":            max_level,
                "event_count":          event_count,
                "correlation_strength": corr,
                "mitre_ids":            sorted(mitre_ids),
                "mitre_tactics":        sorted(mitre_tactics),
                "mitre_techniques":     sorted(mitre_techniques),
                "commands":             sorted(commands),
                "file_paths":           sorted(file_paths),
                "timestamps":           timestamps,
                "timestamp":            timestamps[0] if timestamps else "",
            },
        })

    return chunks


def _dominant_attack(attack_types: set) -> str:
    priority = [
        "rootkit", "malware", "lateral_movement", "exfiltration", "account_compromise",
        "privilege_escalation", "brute_force", "defense_evasion",
        "web_attack", "network_anomaly", "authentication_success",
        "file_integrity", "network_change", "system_change",
        "removable_media", "authentication", "other",
    ]
    for p in priority:
        if p in attack_types:
            return p
    return next(iter(attack_types), "other")


def chunk_generic_alerts(data: Any) -> List[dict]:
    if isinstance(data, dict) and "alerts" in data:
        alerts = data["alerts"]
    elif isinstance(data, list):
        alerts = data
    else:
        alerts = [data]

    chunks = []
    for alert in alerts:
        parts = [f"[ALERT] id={alert.get('id', 'N/A')} ts={alert.get('timestamp', 'N/A')}"]
        if alert.get("event_type"):
            parts.append(f"event_type={alert['event_type']}")
        if alert.get("severity"):
            parts.append(f"severity={alert['severity'].upper()}")
        if alert.get("source_ip") or alert.get("destination_ip"):
            parts.append(
                f"src={alert.get('source_ip', 'N/A')} dst={alert.get('destination_ip', 'N/A')}"
            )
        if alert.get("description"):
            parts.append(f"description={alert['description'][:200]}")

        known = {"id", "timestamp", "event_type", "severity",
                 "source_ip", "destination_ip", "description", "project"}
        for key, val in alert.items():
            if key not in known and val:
                parts.append(f"{key}={str(val)[:150]}")

        chunks.append({
            "text": "\n".join(parts),
            "metadata": {
                "source":     "generic_alerts",
                "alert_id":   alert.get("id", ""),
                "severity":   alert.get("severity", ""),
                "event_type": alert.get("event_type", ""),
                "timestamp":  alert.get("timestamp", ""),
                "max_level":  0,
            },
        })
    return chunks


def chunk_thehive(records: Any) -> List[dict]:
    if isinstance(records, dict):
        records = records.get("data", [records])

    chunks = []
    for case in records:
        _type = case.get("_type", "unknown")
        if _type == "case":
            text = (
                f"[THEHIVE CASE] #{case.get('caseId', '?')} — {case.get('title', '')}\n"
                f"severity={case.get('severity', '?')} | status={case.get('status', '?')}\n"
                f"description={case.get('description', '')[:400]}\n"
                f"tags={', '.join(case.get('tags', []))}"
            )
        elif _type == "alert":
            text = (
                f"[THEHIVE ALERT] {case.get('title', '')}\n"
                f"type={case.get('type', '?')} | source={case.get('source', '?')}\n"
                f"description={case.get('description', '')[:400]}"
            )
        else:
            text = f"[THEHIVE] {json.dumps(case)[:500]}"

        chunks.append({
            "text": text,
            "metadata": {
                "source":    "thehive",
                "type":      _type,
                "case_id":   case.get("caseId", ""),
                "severity":  case.get("severity", ""),
                "max_level": int(case.get("severity", 0) or 0),
            },
        })
    return chunks


def chunk_suricata(records: List[dict]) -> List[dict]:
    chunks = []
    for evt in records:
        event_type = evt.get("event_type", "")
        text = (
            f"[SURICATA {event_type.upper()}] ts={evt.get('timestamp', '')}\n"
            f"src={evt.get('src_ip', '')}:{evt.get('src_port', '')}"
            f" -> dst={evt.get('dest_ip', '')}:{evt.get('dest_port', '')}\n"
            f"proto={evt.get('proto', '')}"
        )
        severity = 0
        if event_type == "alert":
            sig = evt.get("alert", {})
            text += f"\nsignature={sig.get('signature', '')}\ncategory={sig.get('category', '')}"
            severity = sig.get("severity", 0) or 0

        chunks.append({
            "text": text,
            "metadata": {
                "source":     "suricata",
                "event_type": event_type,
                "src_ip":     evt.get("src_ip", ""),
                "dest_ip":    evt.get("dest_ip", ""),
                "max_level":  int(severity),
            },
        })
    return chunks


def chunk_generic(records: Any) -> List[dict]:
    if isinstance(records, dict):
        records = [records]
    chunks = []
    for i, record in enumerate(records):
        text = f"[RECORD {i + 1}]\n"
        for key, val in record.items():
            text += f"{key}: {str(val)[:200]}\n"
        chunks.append({
            "text": text[:800],
            "metadata": {"source": "unknown", "index": i, "max_level": 0},
        })
    return chunks


# ======= DISPATCH =======

CHUNKERS = {
    "wazuh":          chunk_wazuh,
    "generic_alerts": chunk_generic_alerts,
    "thehive":        chunk_thehive,
    "suricata":       chunk_suricata,
    "elastic":        chunk_generic,
    "elastic_search": chunk_generic,
    "unknown":        chunk_generic,
}


def process_json_file(file_path: str) -> List[dict]:
    """
    Load, detect schema, and chunk a JSON/NDJSON log file.
    Returns list of {"text": str, "metadata": dict}.
    """
    try:
        data, schema = load_json_file(file_path)
        if data is None:
            return []
        count = (
            len(data["alerts"]) if isinstance(data, dict) and "alerts" in data
            else (len(data) if isinstance(data, list) else 1)
        )
        print(f"[SchemaDetector] schema={schema} | records={count} | file={file_path}")
        chunker = CHUNKERS.get(schema, chunk_generic)
        return chunker(data)
    except Exception as e:
        print(f"[process_json_file] Error processing {file_path}: {e}")
        return []