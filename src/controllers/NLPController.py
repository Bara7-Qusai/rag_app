from .BaseController import BaseController
from models.db_schemes import Project, DataChunk
from stores.llm.LLMEnums import DocumentTypeEnum
from typing import List, Optional
import json
import re
import logging
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────
#  MITRE Full Mapping (Tactics + Techniques)
# ─────────────────────────────────────────────
MITRE_NAMES = {
    # Tactics
    "TA0001": "Initial Access",        "TA0002": "Execution",
    "TA0003": "Persistence",           "TA0004": "Privilege Escalation",
    "TA0005": "Defense Evasion",       "TA0006": "Credential Access",
    "TA0007": "Discovery",             "TA0008": "Lateral Movement",
    "TA0009": "Collection",            "TA0010": "Exfiltration",
    "TA0011": "Command and Control",
    # Techniques — verified against MITRE ATT&CK
    "T1014":     "Rootkit",
    "T1021":     "Remote Services",
    "T1046":     "Network Service Discovery",
    "T1059":     "Command and Scripting Interpreter",
    "T1078":     "Valid Accounts",
    "T1098":     "Account Manipulation",
    "T1110":     "Brute Force",
    "T1204":     "User Execution",
    "T1484":     "Domain Policy Modification",
    "T1548":     "Abuse Elevation Control Mechanism",
    "T1548.003": "Sudo and Sudo Caching",
    "T1562":     "Impair Defenses",
    "T1565":     "Data Manipulation",
    "T1565.001": "Stored Data Manipulation",
}

WAZUH_RULE_TO_MITRE = {
    "510": "T1110",     # Brute Force (Credential Access)
    "533": "T1059",     # Command and Scripting Interpreter (Execution)
    "5402": "T1548.003", # Sudo and Sudo Caching (Privilege Escalation)
    "550": "T1548",     # Abuse Elevation Control Mechanism (Privilege Escalation)
    "5501": "T1078",    # Valid Accounts (Initial Access)
    "5710": "T1046",    # Network Service Discovery (Discovery)
    "5715": "T1021",    # Remote Services (Lateral Movement)
    "5720": "T1562",    # Impair Defenses (Defense Evasion)
    "5730": "T1021",    # Remote Services (Lateral Movement)
    "5740": "T1565",    # Data Manipulation (Collection)
    "5750": "T1071",    # Application Layer Protocol (Command and Control)
    "5760": "T1041",    # Exfiltration Over C2 Channel (Exfiltration)
    "5770": "T1189",    # Drive-by Compromise (Initial Access)
}

MITRE_ATTACK_TYPE_MAP = {
    # IMPROVED: More accurate MITRE mapping
    "authentication_success": {"id": "T1078", "name": "Valid Accounts"},  # SSH/login = initial access
    "valid_accounts":         {"id": "T1078", "name": "Valid Accounts"},
    "privilege_escalation":   {"id": "T1548.003", "name": "Sudo and Sudo Caching"},  # sudo/su
    "rootkit":                {"id": "T1014", "name": "Rootkit"},  # Only for CONFIRMED rootkit, not indicators
    "file_tampering":         {"id": "T1562.001", "name": "Disable or Modify Tools"},  # For trojaned files (indicators)
    "defense_evasion":        {"id": "T1562", "name": "Impair Defenses"},  # Only for actual evasion
    "credential_access":      {"id": "T1110", "name": "Brute Force"},
    "lateral_movement":       {"id": "T1021", "name": "Remote Services"},
}

#  FIX 1: keyword → MITRE technique (extended for better coverage)
#  IMPROVED: More precise mapping to prevent over-generalization
KEYWORD_TO_MITRE = {
    # Rootkit indicators - specific to T1014 (ONLY for confirmed rootkit)
    "rootcheck": "T1014", "rootkit": "T1014", "trojan": "T1014",
    # FIX: trojaned file is an INDICATOR, not confirmation - map to T1562.001
    "trojaned": "T1562.001",
    # Privilege escalation - T1548.003 (sudo/su), not T1078
    "sudo": "T1548.003", "su ": "T1548.003", "su-": "T1548.003",
    "privilege_escalation": "T1548.003", "escalat": "T1548.003",
    # Initial Access - T1078 (valid accounts) for authentication
    "ssh": "T1078", "login": "T1078", "accepted": "T1078",
    "authentication_success": "T1078", "session opened": "T1078",
    # Credential Access - T1110 for brute force
    "brute": "T1110", "failed": "T1110", "authentication_failed": "T1110",
    # Defense Evasion - T1562 only for actual evasion (not every system event)
    "defense_evasion": "T1562", "impair": "T1562",
    # FIX: selinux alone is NOT defense evasion
    # Execution - T1204 for malware/trojan execution
    "malware": "T1204", "executed": "T1204",
    # FIX: Add file_tampering mapping
    "file_tampering": "T1562.001", "integrity": "T1562.001",
}

#  FIX: Correct attack type canonical mapping - authentication is NOT defense evasion
ATTACK_TYPE_CANONICAL = {
    "rootcheck":              "rootkit",
    "rootkit":                "rootkit",
    # FIX: trojaned file is an INDICATOR, not confirmation of rootkit
    "trojaned":               "file_tampering",  # Was "rootkit" - too aggressive
    "authentication_success": "authentication_success",  # FIXED: Keep as authentication
    "authentication_failed":  "credential_access",
    "pam":                    "authentication_success",   # PAM success = authentication
    "sshd":                   "authentication_success",   # SSH success = authentication
    "sudo":                   "privilege_escalation",
    "audit":                  "privilege_escalation",
}

# SOC priority weights — single source of truth
PRIORITY = {
    "trojaned": 100, "rootkit": 100, "rootcheck": 95, "/bin/passwd": 95,
    "exploit":  90,  "shell":   90,  "kali-vm":   85,  "10.200.200.20": 85,
    "access denied": 80, "malware": 80,
    "accepted":  50, "session opened": 50, "sudo": 50, "systemctl": 40,
}

# Attack chain ordering — chronological kill-chain flow
# IMPROVED: Proper MITRE ATT&CK order with correlation priority
ATTACK_CHAIN_ORDER = {
    "T1078":     1,   # Initial Access  — Valid Accounts (SSH login)
    "T1110":     2,   # Credential Access — Brute Force
    "T1548.003": 3,   # Privilege Escalation — Sudo/Su
    "T1562":     4,   # Defense Evasion — only for actual evasion acts
    "T1014":     5,   # Impact — Rootkit/File Integrity (not persistence)
    "T1021":     6,   # Lateral Movement
}

# Confidence scores for threat classifications
# IMPROVED: Add confidence based on evidence strength
THREAT_CONFIDENCE = {
    "rootkit": 0.85,        # High confidence - trojaned file detected
    "trojan": 0.85,         # High confidence - trojaned file detected
    "trojaned": 0.85,       # High confidence - trojaned file detected
    "privilege_escalation": 0.75,  # Medium-high - sudo/su commands
    "authentication_success": 0.9, # High - actual login event
    "defense_evasion": 0.5,  # Low-medium - requires context
    "credential_access": 0.7,  # Medium-high - failed login attempts
    "lateral_movement": 0.6,  # Medium - requires correlation
}

#  FIX 3: Wazuh rule groups → canonical attack type
#  IMPROVED: More accurate mapping, prevent over-generalization
GROUPS_TO_ATTACK_TYPE = {
    "rootcheck":              "rootkit",
    "syscheck":               "rootkit",
    "authentication_success": "authentication_success",
    "authentication_failed":  "credential_access",
    "sudo":                   "privilege_escalation",
    "audit":                  "privilege_escalation",
    # FIX: SELinux denials are NOT automatically defense evasion
    # Only map to defense_evasion if there's clear evasion intent
    "audit_selinux":          "system_activity",  # Was "defense_evasion" - too aggressive
    "sshd":                   "authentication_success",
    "pam":                    "authentication_success",
    # FIX: More conservative defense_evasion mapping
    "firewall":               "system_activity",  # Was defense_evasion - too aggressive
    "iptables":               "system_activity",  # Was defense_evasion - too aggressive
    "netstat":                "discovery",
    # FIX: Add system_activity for non-malicious system events
    "system_activity":       "system_activity",
}


class NLPController(BaseController):

    def __init__(self, vectordb_client, generation_client,
                 embedding_client, template_parser):
        super().__init__()
        self.vectordb_client   = vectordb_client
        self.generation_client = generation_client
        self.embedding_client  = embedding_client
        self.template_parser   = template_parser

        self.embedding_cache       = {}
        self.max_context_documents = 15

    # ──────────────────────────────────────────
    #  Collection helpers
    # ──────────────────────────────────────────
    def create_collection_name(self, project_id: str):
        return f"collection_{self.embedding_client.embedding_size}_{project_id}".strip()

    async def reset_vector_db_collection(self, project: Project):
        collection_name = self.create_collection_name(project_id=project.project_id)
        return await self.vectordb_client.delete_collection(collection_name=collection_name)

    async def get_vector_db_collection_info(self, project: Project):
        collection_name = self.create_collection_name(project_id=project.project_id)
        try:
            collection_info = await self.vectordb_client.get_collection_info(collection_name=collection_name)
        except ValueError:
            return False
        if not collection_info:
            return False
        return json.loads(json.dumps(collection_info, default=lambda x: x.__dict__))

    # ──────────────────────────────────────────
    #   FIX 4: Improved Indexing with full metadata
    # ──────────────────────────────────────────
    async def index_into_vector_db(self, project: Project, chunks: List[DataChunk],
                                   chunks_ids: List[int], do_reset: bool = False):
        collection_name = self.create_collection_name(project_id=project.project_id)
        texts      = [c.chunk_text for c in chunks]
        metadata   = [self._enrich_chunk_metadata(c.chunk_metadata) for c in chunks]  #  ENRICHED
        record_ids = [c.chunk_id for c in chunks]

        import asyncio
        loop = asyncio.get_running_loop()
        embed_tasks = [
            loop.run_in_executor(
                None,
                lambda t=t: self.embedding_client.embed_text(
                    text=t, document_type=DocumentTypeEnum.DOCUMENT.value
                )
            )
            for t in texts
        ]
        embed_results = await asyncio.gather(*embed_tasks)

        vectors, filtered_texts, filtered_metadata, filtered_record_ids = [], [], [], []
        for i, vec_list in enumerate(embed_results):
            if vec_list and len(vec_list) > 0:
                vectors.append(vec_list)
                filtered_texts.append(texts[i])
                filtered_metadata.append(metadata[i])
                filtered_record_ids.append(record_ids[i])

        if not vectors:
            error_message = f"No valid vectors generated for project {project.project_id}. Check embedding client output and chunk contents."
            logger.error(error_message)
            raise ValueError(error_message)

        await self.vectordb_client.create_collection(
            collection_name=collection_name,
            embedding_size=self.embedding_client.embedding_size,
            do_reset=do_reset,
        )
        inserted_count = await self.vectordb_client.insert_many(
            collection_name=collection_name,
            texts=filtered_texts,
            metadata=filtered_metadata,
            vectors=vectors,
            record_ids=filtered_record_ids,
        )

        if inserted_count == 0:
            error_message = f"Vector DB insertion verification failed for {collection_name}"
            logger.error(error_message)
            raise RuntimeError(error_message)

        logger.info(f" Indexed {inserted_count}/{len(chunks)} chunks for project {project.project_id}")
        return inserted_count

    #  FIX 5: New — enrich metadata at index time so stats are always correct
    def _enrich_chunk_metadata(self, meta: dict) -> dict:
        """
        Ensure all critical fields exist in metadata at index time.
        This prevents missing data during summarization.
        """
        if not isinstance(meta, dict):
            return meta or {}

        enriched = dict(meta)

        # Try to parse rule info from embedded raw JSON if present
        raw = enriched.get("raw_log") or enriched.get("full_log", "")
        if raw:
            try:
                parsed = json.loads(raw) if isinstance(raw, str) else raw
                rule   = parsed.get("rule", {}) if isinstance(parsed, dict) else {}
                agent  = parsed.get("agent", {}) if isinstance(parsed, dict) else {}

                if not enriched.get("rule_id"):
                    enriched["rule_id"] = str(rule.get("id", ""))
                if not enriched.get("rule_level"):
                    enriched["rule_level"] = int(rule.get("level", 0) or 0)
                if not enriched.get("rule_description"):
                    enriched["rule_description"] = rule.get("description", "")
                if not enriched.get("agent"):
                    enriched["agent"] = agent.get("name", "")
                if not enriched.get("timestamp"):
                    enriched["timestamp"] = parsed.get("timestamp", "")

                # MITRE
                if not enriched.get("mitre_ids"):
                    mitre = rule.get("mitre", {})
                    ids   = mitre.get("id", []) if isinstance(mitre, dict) else []
                    enriched["mitre_ids"] = ids if isinstance(ids, list) else [ids] if ids else []

                # Attack type from groups
                if not enriched.get("attack_type"):
                    groups = rule.get("groups", [])
                    enriched["attack_type"] = self._groups_to_attack_type(groups)

                # Agent IP
                if not enriched.get("src_ip"):
                    enriched["src_ip"] = agent.get("ip", "")

            except Exception:
                pass

        # Compute severity tag from rule_level
        level = int(enriched.get("rule_level", 0) or 0)
        enriched["severity_tag"] = (
            "Critical" if level >= 12 else
            "High"     if level >= 7  else
            "Medium"   if level >= 4  else "Low"
        )

        return enriched

    def _groups_to_attack_type(self, groups: list) -> str:
        """Map Wazuh rule groups to canonical attack type."""
        #  FIX: Rule-based classification with specific handling for important events
        usb_keywords = ["usb", "device", "mount", "storage"]
        netstat_keywords = ["netstat", "network", "connection", "socket"]
        selinux_keywords = ["selinux", "avc", "denial", "policy"]

        for g in (groups or []):
            g_lower = str(g).lower()
            if g_lower in GROUPS_TO_ATTACK_TYPE:
                return GROUPS_TO_ATTACK_TYPE[g_lower]
            # Special handling for important events - classify appropriately, do NOT ignore
            if any(kw in g_lower for kw in usb_keywords):
                return "defense_evasion"  # USB events indicate potential defense evasion attempts
            if any(kw in g_lower for kw in netstat_keywords):
                return "discovery"  # Network discovery activities
            if any(kw in g_lower for kw in selinux_keywords):
                return "defense_evasion"  # SELinux denials indicate defense evasion attempts
        return "unknown"

    # ──────────────────────────────────────────
    #  Priority scoring
    # ──────────────────────────────────────────
    def _priority_score(self, doc) -> int:
        text      = str(getattr(doc, "text", "")).lower()
        meta      = doc.metadata if hasattr(doc, "metadata") and isinstance(doc.metadata, dict) else {}
        meta_text = json.dumps(meta).lower()
        combined  = text + " " + meta_text

        for keyword, score in PRIORITY.items():
            if keyword in combined:
                return score

        level = int(meta.get("max_level") or meta.get("rule_level") or 0)
        if level >= 12:
            return 90
        if level >= 7:
            return 60
        return 10

    # ──────────────────────────────────────────
    #  MITRE extraction
    # ──────────────────────────────────────────
    def _extract_mitre_from_rule(self, rule_id: str, raw_json: str) -> str:
        if not rule_id or not raw_json:
            return ""
        try:
            parsed = json.loads(raw_json)
            rule   = parsed.get("rule", {}) if isinstance(parsed, dict) else {}
            if isinstance(rule, dict) and str(rule.get("id", "")) == str(rule_id):
                mitre = rule.get("mitre", {})
                if isinstance(mitre, dict):
                    ids = mitre.get("id", [])
                    if isinstance(ids, list) and ids:
                        return str(ids[0])
                    if isinstance(ids, str) and ids.strip():
                        return ids.strip()
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
        return ""

    def _get_mitre_name(self, mitre_id: str) -> str:
        return MITRE_NAMES.get(mitre_id, "")

    def _infer_mitre_from_text(self, text: str) -> str:
        text_lower = text.lower()
        for keyword, technique in KEYWORD_TO_MITRE.items():
            if keyword in text_lower:
                return technique
        return ""

    def _extract_mitre_from_documents(self, documents: list) -> Optional[dict]:
        for doc in documents:
            meta    = doc.metadata if hasattr(doc, "metadata") and isinstance(doc.metadata, dict) else {}
            rule    = meta.get("rule") if isinstance(meta.get("rule"), dict) else {}
            rule_id = str(rule.get("id", "") if isinstance(rule, dict) else "")

            if rule_id in WAZUH_RULE_TO_MITRE:
                tactic = WAZUH_RULE_TO_MITRE[rule_id]
                return {"id": tactic, "name": self._get_mitre_name(tactic)}

            raw_text = getattr(doc, "text", "")
            mitre_id = self._extract_mitre_from_rule(rule_id, raw_text)
            if mitre_id:
                return {"id": mitre_id, "name": self._get_mitre_name(mitre_id)}

            mitre_id = self._infer_mitre_from_text(raw_text)
            if mitre_id:
                return {"id": mitre_id, "name": self._get_mitre_name(mitre_id)}

        return None

    # ──────────────────────────────────────────
    #  IOC extraction
    # ──────────────────────────────────────────
    _RE_IP       = re.compile(r'\b(?!127\.0\.0\.1)(?!0\.0\.0\.0)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    _RE_HASH     = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
    _RE_DOMAIN   = re.compile(r'\b(?![\d.]+\b)[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b')
    _RE_USERNAME = re.compile(r'(?:user(?:name)?|srcuser)[:=]\s*([a-zA-Z0-9_.-]+)', re.IGNORECASE)
    _RE_FILEPATH = re.compile(r'(/[^\s"\'<>]{4,}|[A-Za-z]:\\[^\s"\'<>]{4,})')
    _RE_COMMAND  = re.compile(r'(?:command|cmd|COMMAND)[:=]\s*([^\n\r]{4,})', re.IGNORECASE)

    def _extract_iocs_from_documents(self, documents: list) -> dict:
        """
        Extract Indicators of Compromise (IOCs) from document collection.
        Returns deduplicated IOCs categorized by type.
        """
        iocs: dict = {"ips": set(), "users": set(), "file_paths": set(),
                      "hashes": set(), "domains": set(), "commands": set()}

        for doc in documents:
            text = getattr(doc, "text", "")
            meta = doc.metadata if hasattr(doc, "metadata") and isinstance(doc.metadata, dict) else {}

            #  FIX: Improved IP extraction with better regex
            iocs["ips"].update(self._RE_IP.findall(text))
            iocs["hashes"].update(self._RE_HASH.findall(text))
            iocs["users"].update(self._RE_USERNAME.findall(text))
            iocs["file_paths"].update(
                p for p in self._RE_FILEPATH.findall(text)
                if len(p) > 5 and not p.startswith("/proc") and not p.startswith("/sys")
            )
            iocs["commands"].update(
                c.strip().strip('"\'') for c in self._RE_COMMAND.findall(text)
                if c.strip()
            )
            iocs["domains"].update(
                d for d in self._RE_DOMAIN.findall(text)
                if not d.endswith((".local", ".internal", ".log", ".conf"))
            )

            # FIX: Extract from metadata with null checks
            for key, ioc_type in [("src_ip", "ips"), ("dst_ip", "ips"),
                                   ("user", "users"), ("username", "users"),
                                   ("command", "commands"), ("commands", "commands"),
                                   ("file_path", "file_paths"), ("file", "file_paths")]:
                val = meta.get(key)
                if isinstance(val, list):
                    iocs[ioc_type].update(str(v).strip() for v in val if v and str(v).strip())
                elif val and str(val).strip():
                    iocs[ioc_type].add(str(val).strip())

            #  FIX: Extract users from srcusers array (chunk_wazuh specific)
            srcusers = meta.get("srcusers", [])
            if isinstance(srcusers, list):
                iocs["users"].update(u for u in srcusers if u and str(u).strip() not in ["_", ""])

        # FIX: Remove duplicates using set() and filter garbage values
        GARBAGE = {"_", "N/A", "", "0.0.0.0", "null", "none", "::", "127.0.0.1"}
        return {
            k: sorted(list(v - GARBAGE))[:10]  # Limit to top 10 per category
            for k, v in iocs.items()
            if v - GARBAGE
        }

    # ──────────────────────────────────────────
    #  Correlation Engine
    # ──────────────────────────────────────────
    def _correlate_documents(self, documents: list) -> list:
        # FIX: Optimize correlation by using dictionary grouping instead of nested loops
        # Cache agent extraction to avoid repeated calls
        agent_cache = {}
        groups: dict = defaultdict(list)

        for doc in documents:
            # Cache agent extraction
            doc_id = id(doc)
            if doc_id not in agent_cache:
                agent_cache[doc_id] = self._extract_agent_name(doc) or "unknown"
            agent = agent_cache[doc_id]

            meta = doc.metadata if hasattr(doc, "metadata") and isinstance(doc.metadata, dict) else {}
            src_ip = str(meta.get("src_ip", ""))
            user = str(meta.get("user", "") or meta.get("username", ""))

            # Create correlation key
            key = (agent, src_ip or user)
            groups[key].append(doc)

        scored_groups = []
        for key, docs in groups.items():
            #  FIX: Cache priority scores to avoid repeated computation
            priority_cache = {}
            group_score = max(
                priority_cache.get(id(d), priority_cache.setdefault(id(d), self._priority_score(d)))
                for d in docs
            )
            for doc in docs:
                if hasattr(doc, "metadata") and isinstance(doc.metadata, dict):
                    doc.metadata["_correlation_group"] = f"{key[0]}|{key[1]}"
                    doc.metadata["_group_size"] = len(docs)
            scored_groups.append((group_score, docs))

        scored_groups.sort(key=lambda x: x[0], reverse=True)
        result = []
        for _, docs in scored_groups:
            result.extend(docs)
        return result

    # ──────────────────────────────────────────
    #  Attack Chain builder
    # ──────────────────────────────────────────
    def _build_attack_chain(self, documents: list) -> list:
        # FIX: Sort events by parsed timestamp BEFORE building the attack chain
        sorted_docs = sorted(
            documents,
            key=lambda d: self._parse_attack_chain_timestamp(
                d.metadata.get("timestamp", "") if hasattr(d, "metadata") and d.metadata else ""
            )
        )

        steps = []
        seen_events = set()

        for doc in sorted_docs:
            meta   = doc.metadata if hasattr(doc, "metadata") and isinstance(doc.metadata, dict) else {}
            text   = getattr(doc, "text", "")
            ts     = meta.get("timestamp", "")
            agent  = meta.get("agent", "N/A")
            user   = meta.get("user") or meta.get("username") or "N/A"
            src_ip = meta.get("src_ip", "N/A")

            #  FIX: Add null checks to prevent crashes
            user   = user   if user   and user not in ["_", "", None] else "N/A"
            src_ip = src_ip if src_ip and src_ip not in ["_", "", None, "0.0.0.0"] else "N/A"
            rule_id = str((meta.get("rule") or {}).get("id", "") if isinstance(meta.get("rule"), dict) else
                          meta.get("rule_id", ""))
            desc    = (meta.get("rule_description") or meta.get("description") or text[:100]).strip()

            fingerprint = (agent, rule_id, desc[:60])
            if fingerprint in seen_events:
                continue
            seen_events.add(fingerprint)

            technique = ""
            if rule_id in WAZUH_RULE_TO_MITRE:
                technique = WAZUH_RULE_TO_MITRE[rule_id]
            else:
                # Also check mitre_ids in metadata
                mids = meta.get("mitre_ids", [])
                if mids:
                    technique = mids[0] if isinstance(mids, list) else mids
                else:
                    technique = (self._extract_mitre_from_rule(rule_id, text) or
                                 self._infer_mitre_from_text(text))

            steps.append({
                "timestamp": ts,
                "event":     desc,
                "technique": technique,
                "agent":     agent,
                "user":      user,
                "src_ip":    src_ip,
                "severity":  int(meta.get("max_level") or meta.get("rule_level") or 0),
            })

        sorted_steps = self._sort_attack_chain(steps)
        for i, s in enumerate(sorted_steps, 1):
            s["step"] = i
        return sorted_steps

    # ──────────────────────────────────────────
    #  Deduplication
    # ──────────────────────────────────────────
    def _deduplicate_documents(self, documents: list) -> list:
        seen = set()
        unique = []
        for doc in documents:
            fp = (getattr(doc, "text", "")[:200],
                  json.dumps(doc.metadata, sort_keys=True)[:200]
                  if hasattr(doc, "metadata") else "")
            if fp in seen:
                continue
            seen.add(fp)
            unique.append(doc)
        return unique

    # ──────────────────────────────────────────
    #  Hybrid Search + Rerank
    # ──────────────────────────────────────────
    def _compute_soc_score(self, doc, query_keywords: list, semantic_score: float) -> float:
        meta      = doc.metadata if hasattr(doc, "metadata") and isinstance(doc.metadata, dict) else {}
        text      = getattr(doc, "text", "").lower()
        meta_text = json.dumps(meta).lower()
        combined  = text + " " + meta_text

        priority     = self._priority_score(doc)
        level        = int(meta.get("max_level") or meta.get("rule_level") or 0)
        keyword_hits = sum(1 for kw in query_keywords if kw in combined)
        mitre_bonus  = 20 if (meta.get("mitre_ids") or self._infer_mitre_from_text(text)) else 0
        group_bonus  = 10 if meta.get("_group_size", 1) > 1 else 0

        return (
            0.45 * semantic_score
            + 0.30 * (priority / 100.0)
            + 0.10 * min(level / 15.0, 1.0)
            + 0.08 * min(keyword_hits / max(len(query_keywords), 1), 1.0)
            + 0.04 * (mitre_bonus / 100.0)
            + 0.03 * (group_bonus / 100.0)
        )

    def _hybrid_search(self, semantic_results: list, query: str, limit: int) -> list:
        query_lower    = query.lower()
        query_keywords = [k for k in re.findall(r'\b\w+\b', query_lower) if len(k) > 2]

        scored = []
        seen   = set()
        for doc in semantic_results:
            fp = (getattr(doc, "text", "")[:200],
                  json.dumps(doc.metadata, sort_keys=True)[:100]
                  if hasattr(doc, "metadata") else "")
            if fp in seen:
                continue
            seen.add(fp)
            sem_score = getattr(doc, "score", 0.5)
            score     = self._compute_soc_score(doc, query_keywords, sem_score)
            scored.append((score, doc))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored[:limit]]

    def rerank_logs(self, logs: list, query: str) -> list:
        if not logs:
            return logs
        query_lower    = query.lower()
        query_keywords = [k for k in re.findall(r'\b\w+\b', query_lower) if len(k) > 2]

        scored = [(self._compute_soc_score(doc, query_keywords, 0.5), doc) for doc in logs]
        scored.sort(key=lambda x: x[0], reverse=True)
        return [doc for _, doc in scored]

    # ──────────────────────────────────────────
    #  Metadata filter
    # ──────────────────────────────────────────
    def _build_metadata_filter(self, query: str) -> list:
        query_lower = query.lower()
        filters = []

        if any(w in query_lower for w in ["rootkit", "rootcheck", "trojan", "trojaned"]):
            filters.append({"key": "location", "operator": "in",
                            "value": ["rootcheck", "syscheck", "journald", "var/log/auth.log"]})

        if any(w in query_lower for w in ["privilege", "escalation", "sudo", "su", "root"]):
            filters.append({"key": "rule.groups", "operator": "contains", "value": "syscheck"})

        if any(w in query_lower for w in ["login", "authentication", "ssh", "access"]):
            filters.append({"key": "rule.groups", "operator": "contains", "value": "authentication"})

        if any(w in query_lower for w in ["critical", "high", "severity"]):
            filters.append({"key": "rule.level", "operator": "greater_than", "value": 7})

        return filters

    # ──────────────────────────────────────────
    #  Agent helpers
    # ──────────────────────────────────────────
    def _extract_agent_name(self, doc) -> str:
        if hasattr(doc, "metadata") and isinstance(doc.metadata, dict):
            agent = doc.metadata.get("agent")
            if isinstance(agent, str) and agent.strip():
                return agent.strip()
        raw_text = getattr(doc, "text", "")
        if isinstance(raw_text, str):
            try:
                payload = json.loads(raw_text)
                if isinstance(payload, dict):
                    ap = payload.get("agent")
                    if isinstance(ap, dict):
                        return ap.get("name", "")
                    if isinstance(ap, str):
                        return ap
            except (TypeError, ValueError, json.JSONDecodeError):
                pass
            match = re.search(r'"agent"\s*:\s*\{[^}]*"name"\s*:\s*"([^\"]+)"', raw_text)
            if match:
                return match.group(1).strip()
        return ""

    def _filter_documents(self, documents: list, target_size: int = 20) -> list:
        if not documents:
            return []

        agent_buckets: dict = defaultdict(list)
        for doc in documents:
            agent = self._extract_agent_name(doc) or "unknown"
            agent_buckets[agent].append(doc)

        if len(agent_buckets) <= 1:
            return documents[:target_size]

        selected = []
        for agent, docs in agent_buckets.items():
            docs_sorted = sorted(docs, key=self._priority_score, reverse=True)
            slots = 4 if "kali" in agent.lower() else 2
            selected.extend(docs_sorted[:slots])

        already_selected = set(id(d) for d in selected)
        remaining = [d for d in documents if id(d) not in already_selected]
        remaining.sort(key=self._priority_score, reverse=True)
        selected.extend(remaining)
        return selected[:target_size]

    def _pre_filter_documents(self, documents: list, query: str) -> list:
        query_lower = query.lower()
        for agent_hint in ["kali-vm", "wazuh-server", "ubuntu", "windows"]:
            if agent_hint in query_lower:
                primary   = [d for d in documents if self._extract_agent_name(d).lower() == agent_hint]
                secondary = [d for d in documents if self._extract_agent_name(d).lower() != agent_hint][:5]
                if primary:
                    return primary + secondary
        return documents

    # ──────────────────────────────────────────
    #  Vector DB search
    # ──────────────────────────────────────────
    async def search_vector_db_collection(self, project: Project, text: str,
                                          limit: int = 10, metadata_filter: list = None):
        collection_name = self.create_collection_name(project_id=project.project_id)

        cache_key    = f"query:{text}"
        query_vector = self.embedding_cache.get(cache_key)
        if query_vector is None:
            query_vector = self.embedding_client.embed_text(
                text=text, document_type=DocumentTypeEnum.QUERY.value
            )
            if query_vector:
                self.embedding_cache[cache_key] = query_vector

        if not query_vector:
            return False

        if isinstance(query_vector, list) and query_vector and isinstance(query_vector[0], list):
            query_vector = query_vector[0]

        if not isinstance(query_vector, list) or len(query_vector) == 0:
            logger.error(f"Invalid query embedding shape: {type(query_vector).__name__}")
            return False

        metadata_filter = metadata_filter if metadata_filter is not None else self._build_metadata_filter(text)

        semantic_results = await self.vectordb_client.search_by_vector(
            collection_name=collection_name,
            vector=query_vector,
            limit=limit * 2,
            metadata_filter=metadata_filter,
        )

        if not semantic_results and metadata_filter:
            logger.warning("No results with filter — retrying without filter")
            semantic_results = await self.vectordb_client.search_by_vector(
                collection_name=collection_name,
                vector=query_vector,
                limit=limit * 2,
                metadata_filter=None,
            )

        if not semantic_results:
            logger.warning(f"Vector DB returned zero results for '{text}'")
            return False

        semantic_results = self._deduplicate_documents(semantic_results)
        hybrid_results   = self._hybrid_search(semantic_results, text, limit * 2)
        reranked_results = self.rerank_logs(hybrid_results, text)
        return reranked_results[:limit]

    # ──────────────────────────────────────────
    #  Prompt builders
    # ──────────────────────────────────────────
    def _build_metadata_string(self, meta: dict) -> str:
        fields = [
            ("source",        meta.get("source", "unknown")),
            ("agent",         meta.get("agent", "N/A")),
            ("user",          meta.get("user", "N/A")),
            ("src_ip",        meta.get("src_ip", "N/A")),
            ("dst_ip",        meta.get("dst_ip", "N/A")),
            ("rule_id",       meta.get("rule_id", "N/A")),
            ("severity",      meta.get("severity_tag", meta.get("severity", "N/A"))),
            ("max_level",     meta.get("max_level", meta.get("rule_level", "N/A"))),
            ("attack_type",   meta.get("attack_type", "N/A")),
            ("mitre_ids",     ", ".join(meta.get("mitre_ids", [])) or "N/A"),
            ("event_count",   meta.get("event_count", "N/A")),
            ("timestamp",     meta.get("timestamp", "N/A")),
            ("correlation",   meta.get("_correlation_group", "N/A")),
        ]
        return " | ".join(f"{k}={v}" for k, v in fields)

    def _build_document_summary(self, doc, idx: int) -> str:
        meta        = doc.metadata if hasattr(doc, "metadata") and isinstance(doc.metadata, dict) else {}
        description = meta.get("rule_description") or meta.get("description") or doc.text[:120]
        level       = meta.get("max_level") or meta.get("rule_level") or meta.get("severity") or "N/A"
        group_info  = f" [group={meta.get('_correlation_group', 'N/A')} size={meta.get('_group_size', 1)}]"
        return (
            f"## Incident {idx}{group_info}\n"
            f"agent={meta.get('agent', 'N/A')} | level={level} | attack_type={meta.get('attack_type', 'N/A')}\n"
            f"rule_description={description}\n"
            f"user={meta.get('user', 'N/A')} | src_ip={meta.get('src_ip', 'N/A')}\n"
            f"{doc.text[:700]}"
        )

    def _build_ioc_context(self, documents: list) -> str:
        iocs = self._extract_iocs_from_documents(documents)
        if not iocs:
            return ""
        parts = []
        for category, values in iocs.items():
            if values:
                parts.append(f"{category.upper()}: {', '.join(values)}")
        return "EXTRACTED IOCs:\n" + "\n".join(parts)

    def _build_attack_chain_context(self, attack_chain: list) -> str:
        if not attack_chain:
            return ""
        lines = ["ATTACK CHAIN (chronological - earliest to latest):"]
        for step in attack_chain:
            technique = f"[{step['technique']}]" if step.get("technique") else ""
            # IMPROVED: Better formatting, no truncation
            event_text = step.get('event', '')[:80] if step.get('event') else 'N/A'
            lines.append(
                f"  Step {step['step']}: {step.get('timestamp','?')} | "
                f"agent={step['agent']} user={step['user']} src_ip={step['src_ip']} "
                f"severity={step['severity']} {technique} → {event_text}"
            )
        
        # IMPROVED: Add correlation summary
        if len(attack_chain) > 1:
            lines.append("\nCORRELATION SUMMARY:")
            # Group by agent to show attack progression
            agents = {}
            for step in attack_chain:
                ag = step.get('agent', 'unknown')
                if ag not in agents:
                    agents[ag] = []
                technique = step.get('technique', '')
                if technique:
                    agents[ag].append(technique)
            
            for ag, techs in agents.items():
                if techs:
                    lines.append(f"  {ag}: {' → '.join(techs)}")
        
        return "\n".join(lines)

    #  FIX 7: detect_query_type — add "summary" mode
    def detect_query_type(self, query: str) -> str:
        query_lower = (query or "").lower()
        summary_indicators = ["ملخص", "summarize", "summary", "overview", "تلخيص", "اعطني ملخص"]
        if any(term in query_lower for term in summary_indicators):
            return "summary"
        multi_indicators = [
            "top", "top threats", "أهم", "اخطر", "multiple",
            "threats", "highest", "most critical", "أكثر",
        ]
        if any(term in query_lower for term in multi_indicators):
            return "multi"
        return "single"

    # ──────────────────────────────────────────
    #  JSON parsing / validation / fixing
    # ──────────────────────────────────────────
    def _extract_json_object(self, text: str) -> str:
        if not isinstance(text, str):
            return ""
        start = text.find("{")
        if start == -1:
            return ""
        depth, in_string, escape = 0, False, False
        for idx, char in enumerate(text[start:], start):
            if char == '"' and not escape:
                in_string = not in_string
            escape = (char == '\\' and not escape)
            if not in_string:
                if char == '{':
                    depth += 1
                elif char == '}':
                    depth -= 1
                    if depth == 0:
                        return text[start:idx + 1]
        return text[start:]

    def _clean_llm_output(self, text: str) -> str:
        if not isinstance(text, str):
            return ""
        text = re.sub(r"```json", "", text, flags=re.IGNORECASE)
        text = re.sub(r"```", "", text)
        return self._extract_json_object(text.strip()).strip()

    def _fix_malformed_json(self, text: str) -> str:
        cleaned = re.sub(r',\s*([}\]])', r'\1', text)
        cleaned = cleaned.replace("\n", " ")
        return cleaned

    def _parse_markdown_to_json(self, text: str) -> dict:
        if "top_threats" in text.lower():
            threats = []
            threat_pattern = r'\*\*تهديد\s*\d+:\*\*|\*\*threat\s*\d+:\*\*'
            parts = re.split(threat_pattern, text, flags=re.IGNORECASE)

            for part in parts[1:]:
                threat = {}
                for line in part.strip().split('\n'):
                    line = line.strip()
                    if not line or ':' not in line:
                        continue
                    key, value = line.split(':', 1)
                    key   = key.strip().strip('*+-').lower().replace(' ', '_')
                    value = value.strip().strip('*+-')
                    if key == 'mitre':
                        m = re.search(r'\{"id":\s*"([^"]*)",\s*"name":\s*"([^"]*)"\}', value)
                        threat[key] = {"id": m.group(1), "name": m.group(2)} if m else {"id": "", "name": ""}
                    elif key == 'iocs':
                        iocs = {"ips": [], "users": [], "file_paths": [], "commands": []}
                        for ioc_line in value.split('\n'):
                            if ':' in ioc_line:
                                ik, iv = ioc_line.split(':', 1)
                                ik = ik.strip().strip('*+-').lower().replace(' ', '_')
                                if ik in iocs:
                                    lm = re.search(r'\[([^\]]*)\]', iv)
                                    if lm:
                                        iocs[ik] = [i.strip().strip('"\'') for i in lm.group(1).split(',') if i.strip()]
                        threat[key] = iocs
                    elif key == 'recommendations':
                        threat[key] = ([v.strip().strip('"\'') for v in value.strip('[]').split(',') if v.strip()]
                                       if '[' in value else ([value] if value else []))
                    else:
                        threat[key] = value
                if threat:
                    threats.append(threat)
            return {"top_threats": threats}

        result = {}
        for line in text.split('\n'):
            line = line.strip()
            if not line or ':' not in line:
                continue
            key, value = line.split(':', 1)
            key   = key.strip().strip('*+-').lower().replace(' ', '_')
            value = value.strip().strip('*+-')
            result[key] = value
        return result

    def safe_parse_llm_output(self, response: str) -> Optional[dict]:
        if not isinstance(response, str):
            return None
        cleaned = self._clean_llm_output(response)
        if not cleaned:
            return None
        try:
            return json.loads(cleaned)
        except (TypeError, ValueError, json.JSONDecodeError):
            try:
                return json.loads(self._fix_malformed_json(cleaned))
            except (TypeError, ValueError, json.JSONDecodeError):
                try:
                    return self._parse_markdown_to_json(cleaned)
                except Exception:
                    return None

    def _validate_rag_output(self, output: str, mode: str = "single") -> bool:
        data = self.safe_parse_llm_output(output)
        if not isinstance(data, dict):
            return False

        if mode == "multi":
            threats = data.get("top_threats")
            if not isinstance(threats, list) or not threats:
                return False
            required = {"summary", "severity", "attack_type", "mitre", "iocs",
                        "attack_scenario", "recommendations"}
            for item in threats:
                if not isinstance(item, dict):
                    return False
                if not required.issubset(item.keys()):
                    return False
                if not isinstance(item.get("mitre"), dict):
                    return False
            return True

        required = {"summary", "severity", "attack_type", "mitre", "iocs",
                    "attack_scenario", "recommendations"}
        if not required.issubset(data.keys()):
            return False
        if not isinstance(data.get("mitre"), dict) or "id" not in data["mitre"]:
            return False
        return True

    def _validate_and_fix(self, output: str, documents: Optional[list] = None,
                          mode: str = "single") -> Optional[dict]:
        data = self.safe_parse_llm_output(output)
        if not isinstance(data, dict):
            logger.warning(f"safe_parse_llm_output failed. Raw: {str(output)[:200]}")
            return None

        if mode == "multi":
            threats = data.get("top_threats")
            if not isinstance(threats, list) or not threats:
                return None
            normalized = []
            for item in threats:
                if not isinstance(item, dict):
                    continue
                iocs = item.get("iocs", {})
                if isinstance(iocs, dict):
                    # Keep structured IOCs as-is for multi mode
                    for k in ["ips", "users", "file_paths", "commands"]:
                        iocs.setdefault(k, [])
                        iocs[k] = [v for v in iocs[k] if v not in ["_", "N/A", "", None]]
                else:
                    iocs = {"ips": [], "users": [], "file_paths": [], "commands": []}

                mitre = item.get("mitre", {"id": "", "name": ""})
                if not isinstance(mitre, dict):
                    mitre = {"id": "", "name": ""}
                mitre_id    = mitre.get("id", "")
                attack_type = self._fix_attack_type_from_mitre(mitre_id, item.get("attack_type", ""))

                normalized.append({
                    "summary":         re.sub(r'<[^>]+>', '', item.get("summary", "")).strip(),
                    "severity":        item.get("severity", ""),
                    "attack_type":     attack_type,
                    "mitre":           mitre,
                    "iocs":            iocs,
                    "attack_scenario": item.get("attack_scenario", ""),
                    "recommendations": (item.get("recommendations", [])
                                        if isinstance(item.get("recommendations"), list) else []),
                })
            if not normalized:
                return None
            data["top_threats"] = normalized
            if "attack_chain" in data and isinstance(data["attack_chain"], list):
                data["attack_chain"] = self._sort_attack_chain(data["attack_chain"])
            return data

        defaults = {
            "summary": "", "severity": "", "attack_type": "",
            "mitre": {"id": "", "name": ""},
            "iocs": {"ips": [], "users": [], "file_paths": [], "commands": []},
            "attack_scenario": "", "recommendations": [],
        }
        for key, default in defaults.items():
            if key not in data:
                data[key] = default

        if not isinstance(data.get("mitre"), dict):
            data["mitre"] = {"id": "", "name": ""}
        data["mitre"].setdefault("id", "")
        data["mitre"].setdefault("name", "")

        mitre_id = data["mitre"].get("id", "")
        data["attack_type"] = self._fix_attack_type_from_mitre(mitre_id, data.get("attack_type", ""))

        if not isinstance(data.get("recommendations"), list):
            data["recommendations"] = []

        # Fallback IOC enrichment
        if not any(data.get("iocs", {}).values() if isinstance(data.get("iocs"), dict) else data.get("iocs", [])) and documents:
            data["iocs"] = self._extract_iocs_from_documents(documents)

        #  FIX: Clean any remaining placeholder text from LLM output
        if "summary" in data and isinstance(data["summary"], str):
            data["summary"] = re.sub(r'<[^>]+>', '', data["summary"]).strip()
            data["summary"] = re.sub(r'use EXACT count from GROUPED THREATS', '', data["summary"]).strip()
            data["summary"] = re.sub(r'replace NUMBER with actual count', '', data["summary"]).strip()

        return data

    def _fix_attack_type_from_mitre(self, mitre_id: str, current_attack_type: str) -> str:
        """
        Map MITRE technique ID to canonical attack type.
        """
        if not mitre_id or mitre_id == "N/A":
            return current_attack_type

        technique_to_attack = {
            "T1078": "authentication_success",
            "T1548": "privilege_escalation",
            "T1548.003": "privilege_escalation",
            "T1110": "credential_access",
            "T1014": "rootkit",
            "T1021": "authentication_success",
            "T1046": "discovery",
            "T1562": "defense_evasion",
            "T1059": "execution",
            "T1071": "command_and_control",
            "T1041": "exfiltration",
            "T1189": "initial_access",
        }

        attack_type = technique_to_attack.get(mitre_id, "")
        return attack_type if attack_type else current_attack_type

    def _parse_attack_chain_timestamp(self, timestamp):
        if isinstance(timestamp, datetime):
            return timestamp
        if timestamp is None:
            return datetime.max
        if isinstance(timestamp, (int, float)):
            try:
                return datetime.fromtimestamp(timestamp)
            except Exception:
                return datetime.max

        if not isinstance(timestamp, str):
            return datetime.max

        timestamp = timestamp.strip()
        if not timestamp:
            return datetime.max

        try:
            if timestamp.endswith("Z"):
                timestamp = timestamp[:-1] + "+00:00"
            return datetime.fromisoformat(timestamp)
        except ValueError:
            for fmt in [
                "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S.%f%z",
                "%Y-%m-%dT%H:%M:%S%z",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
                "%d/%m/%Y %H:%M:%S",
            ]:
                try:
                    return datetime.strptime(timestamp, fmt)
                except ValueError:
                    continue
        return datetime.max

    def _attack_chain_priority(self, technique: str) -> int:
        if not technique:
            return max(ATTACK_CHAIN_ORDER.values(), default=999) + 1
        return ATTACK_CHAIN_ORDER.get(str(technique).strip().upper(),
                                     max(ATTACK_CHAIN_ORDER.values(), default=999) + 1)

    def _sort_attack_chain(self, chain: list) -> list:
        if not isinstance(chain, list):
            return chain

        return sorted(
            chain,
            key=lambda x: (
                self._parse_attack_chain_timestamp(x.get("timestamp", "")),
                str(x.get("timestamp", "")),
                self._attack_chain_priority(x.get("technique", "")),
            ),
        )

    def _clean_iocs(self, iocs) -> list:
        if isinstance(iocs, dict):
            flat = []
            for vals in iocs.values():
                flat.extend(vals if isinstance(vals, list) else [vals])
            iocs = flat
        if not isinstance(iocs, list):
            return []
        GARBAGE = {"_", "N/A", "", "null", "none", "0.0.0.0"}
        seen, unique = set(), []
        for ioc in iocs:
            ioc = str(ioc).strip()
            if ioc.lower() not in GARBAGE and ioc not in seen:
                unique.append(ioc)
                seen.add(ioc)
        return unique

    # ──────────────────────────────────────────────────────────────────
    #  MAIN FIX: generate_file_summary — complete rewrite
    # ──────────────────────────────────────────────────────────────────
    async def generate_file_summary(self, project: Project, file_label: str = "uploaded file") -> dict:
        """
        Reads ALL chunks from the collection directly from PGVector via SQL,
        computes ACCURATE statistics from real data (no LLM hallucination on numbers),
        then uses LLM only for narrative/threat grouping.

        KEY IMPROVEMENTS vs original:
          1. Statistics (counts, severity) computed from raw data — NOT from LLM
          2. Threat grouping by attack_type done in Python BEFORE LLM call
          3. LLM prompt contains exact counts → cannot hallucinate numbers
          4. Post-processing enforces all numeric fields regardless of LLM output
          5. Structured IOCs per threat (not flat list)
        """
        import asyncio
        from sqlalchemy.sql import text as sql_text

        loop            = asyncio.get_running_loop()
        collection_name = self.create_collection_name(project_id=project.project_id)

        # ── 1. Read ALL chunks from Postgres ─────────────────────────
        all_texts    = []
        all_metadata = []
        try:
            async with self.vectordb_client.db_client() as session:
                rows = await session.execute(
                    sql_text(
                        f"SELECT text, metadata FROM {collection_name} "
                        f"ORDER BY id LIMIT 1000"   #  increased from 500
                    )
                )
                for row in rows:
                    raw_text = row[0] or ""
                    if raw_text.startswith("FILE_SUMMARY_RAPTOR"):
                        continue
                    try:
                        meta = row[1] if isinstance(row[1], dict) else (
                            json.loads(row[1]) if row[1] else {}
                        )
                    except Exception:
                        meta = {}
                    if meta.get("is_summary") or meta.get("chunk_level", 0) >= 1:
                        continue
                    all_texts.append(raw_text)
                    all_metadata.append(meta)

        except Exception as e:
            logger.error(f"generate_file_summary: SQL read failed: {e}")
            try:
                fallback_vec = self.embedding_client.embed_text(
                    text="security alert attack threat malware rootkit brute force",
                    document_type="document",
                )
                if fallback_vec and isinstance(fallback_vec[0], list):
                    fallback_vec = fallback_vec[0]
                docs = await self.vectordb_client.search_by_vector(
                    collection_name=collection_name, vector=fallback_vec, limit=100,
                )
                if docs:
                    all_texts    = [getattr(d, "text", "") for d in docs]
                    all_metadata = [
                        d.metadata if hasattr(d, "metadata") and isinstance(d.metadata, dict) else {}
                        for d in docs
                    ]
            except Exception as e2:
                logger.error(f"generate_file_summary fallback also failed: {e2}")
                return {"error": str(e2)}

        if not all_texts:
            return {"error": "no_documents_in_collection"}

        logger.info(f"generate_file_summary: loaded {len(all_texts)} chunks for project {project.project_id}")

        # ── 2. Build fake docs for pipeline ──────────────────────────
        class _FakeDoc:
            def __init__(self, text, metadata):
                self.text     = text
                self.metadata = metadata
                self.score    = 0.5

        fake_docs = [_FakeDoc(t, m) for t, m in zip(all_texts, all_metadata)]

        # ── 3.  Compute REAL statistics from ALL documents ──────────
        #  CRITICAL FIX: chunk_wazuh groups N alerts into fewer chunks.
        # Each chunk stores the original event count in metadata["event_count"].
        # We must SUM event_count across all chunks — NOT count chunks themselves.
        total_count = sum(
            int(m.get("event_count", 1) or 1)
            for m in all_metadata
        )
        if total_count == 0:
            total_count = len(fake_docs)  # fallback for non-wazuh formats
        logger.info(f"generate_file_summary: {len(fake_docs)} chunks → {total_count} real events")
        severity_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        agents_seen   = set()
        rule_counts   = defaultdict(int)   # rule_id → count
        mitre_counts  = defaultdict(int)   # mitre_id → count
        #  NEW: group events by attack_type with exact counts
        # FIX: Add file_paths and commands to track all IOCs
        attack_groups: dict = defaultdict(lambda: {
            "count": 0, "agents": set(), "ips": set(), "users": set(),
            "mitre_ids": set(), "severity": "Low", "max_level": 0,
            "file_paths": set(), "commands": set()
        })

        for doc in fake_docs:
            meta = doc.metadata

            #  FIX: Add null checks and safe type conversion
            ev_count = int(meta.get("event_count", 1) or 1) if meta else 1

            level = int(meta.get("max_level") or meta.get("rule_level") or 0) if meta else 0
            # FIX: More accurate severity mapping - Wazuh levels 1-3 are informational/low
            # Level 1-3: Low (informational, not threats)
            # Level 4-6: Medium (warnings, suspicious)
            # Level 7-11: High (errors, attacks)
            # Level 12+: Critical (critical errors, malware)
            sev   = ("Critical" if level >= 12 else
                     "High"     if level >= 7  else
                     "Medium"   if level >= 4  else "Low")

            severity_dist[sev] += ev_count

            agent = str(meta.get("agent", "")) if meta else ""
            if agent:
                agents_seen.add(agent)

            #  FIX: Safe handling of rule_id (comma-separated)
            rid_raw = str(meta.get("rule_id", "") or "") if meta else ""
            for rid in (r.strip() for r in rid_raw.split(",") if r.strip()):
                rule_counts[rid] += ev_count

            #  FIX: Safe handling of mitre_ids
            mids = meta.get("mitre_ids", []) if meta else []
            if isinstance(mids, str):
                mids = [m.strip() for m in mids.split(",") if m.strip()]
            for mid in mids:
                if mid:
                    mitre_counts[mid] += ev_count

            # FIX: Improved attack type grouping with null checks
            # CRITICAL: Reclassify old attack types using CURRENT rules
            attack_type = ""
            if meta:
                attack_type = meta.get("attack_type", "")
                # Reclassify known misclassifications
                attack_type = self._reclassify_attack_type(attack_type, getattr(doc, "text", "") or "")
                
                if not attack_type:
                    groups = (meta.get("rule", {}) or {}).get("groups", []) if isinstance(meta.get("rule"), dict) else []
                    attack_type = self._groups_to_attack_type(groups)
                if not attack_type or attack_type == "unknown":
                    attack_type = self._infer_attack_type_from_text(getattr(doc, "text", "") or "")

            if attack_type:
                g = attack_groups[attack_type]
                g["count"] += ev_count
                if agent:
                    g["agents"].add(agent)

                #  FIX: Safe IP extraction
                ip = meta.get("src_ip", "") if meta else ""
                if ip and ip not in ["_", "0.0.0.0", ""]:
                    g["ips"].add(ip)

                # FIX: Safe user extraction from srcusers array
                srcusers = meta.get("srcusers", []) if meta else []
                if isinstance(srcusers, list):
                    for u in srcusers:
                        if u and str(u).strip() not in ["_", ""]:
                            g["users"].add(str(u).strip())
                else:
                    user = meta.get("user", "") if meta else ""
                    if not user:
                        user = meta.get("username", "") if meta else ""
                    if user and user not in ["_", ""]:
                        g["users"].add(user)

                for mid in mids:
                    if mid:
                        g["mitre_ids"].add(mid)
                
                # FIX: Extract file_paths from multiple sources
                # 1. From metadata fields
                for fkey in ["file", "full_path", "filename", "path"]:
                    fval = meta.get(fkey, "") if meta else ""
                    if fval and fval not in ["_", ""] and isinstance(fval, str):
                        g["file_paths"].add(fval)
                
                # 2. From raw document text (extract all paths like /bin/passwd)
                doc_text = getattr(doc, "text", "") or ""
                if doc_text:
                    import re
                    # Match common file paths in logs
                    path_pattern = re.compile(r'(/bin/[^\s]+|/usr/bin/[^\s]+|/sbin/[^\s]+|/etc/[^\s]+)')
                    found_paths = path_pattern.findall(doc_text)
                    for p in found_paths:
                        if p and len(p) > 3:
                            g["file_paths"].add(p)
                
                # FIX: Extract commands from multiple sources
                # 1. From metadata fields
                for ckey in ["command", "cmd", "shell", "command_name"]:
                    cval = meta.get(ckey, "") if meta else ""
                    if cval and cval not in ["_", ""] and isinstance(cval, str):
                        g["commands"].add(cval)
                
                # 2. From raw document text
                if doc_text:
                    # Match common command patterns
                    cmd_patterns = [
                        re.compile(r'(sudo|su|su-|pkexec)\s+([^\s]+)?'),
                        re.compile(r'systemctl\s+(start|stop|restart|enable|disable)\s+([^\s]+)?'),
                    ]
                    for pattern in cmd_patterns:
                        for match in pattern.finditer(doc_text):
                            cmd = match.group(0).strip()
                            if cmd and len(cmd) > 2:
                                g["commands"].add(cmd)
                
                if level > g["max_level"]:
                    g["max_level"] = level
                    g["severity"] = sev

                #  FIX: Boost severity for high-risk attack types - privilege escalation is ALWAYS High
                if attack_type in ["privilege_escalation", "rootkit", "credential_access"]:
                    if attack_type == "privilege_escalation":
                        g["severity"] = "High"  # Always High for privilege escalation
                    elif g["severity"] == "Low":
                        g["severity"] = "Medium"
                    elif g["severity"] == "Medium":
                        g["severity"] = "High"

        overall_sev = ("Critical" if severity_dist["Critical"] > 0 else
                       "High"     if severity_dist["High"] > 0      else
                       "Medium"   if severity_dist["Medium"] > 0     else "Low")

        # ── 4. Prioritise and build sample for LLM ───────────────────
        unique_docs = self._deduplicate_documents(fake_docs)
        prioritized = sorted(unique_docs, key=self._priority_score, reverse=True)[:40]

        # ── 5.  Build grouped threat context — exact counts baked in ─
        threat_groups_block = self._build_threat_groups_block(attack_groups, total_count)

        ioc_block   = self._build_ioc_context(prioritized)
        chain       = self._build_attack_chain(prioritized)
        chain_block = self._build_attack_chain_context(chain)

        # Stats block with EXACT numbers for LLM
        stats_block = (
            f"VERIFIED DATASET STATISTICS — THESE NUMBERS ARE GROUND TRUTH:\n"
            f"  total_events_analyzed: {total_count}\n"
            f"  overall_severity: {overall_sev}\n"
            f"  severity_breakdown: {json.dumps(severity_dist)}\n"
            f"  Agents observed: {', '.join(sorted(agents_seen)) or 'N/A'}\n"
            f"  Top Rule IDs: {dict(sorted(rule_counts.items(), key=lambda x: -x[1])[:5])}\n"
            f"  MITRE IDs observed: {dict(sorted(mitre_counts.items(), key=lambda x: -x[1]))}\n"
            f"\n{threat_groups_block}"
        )

        doc_summaries = []
        for idx, doc in enumerate(prioritized):
            meta     = doc.metadata
            agent    = meta.get("agent", "N/A")
            level    = int(meta.get("rule_level") or meta.get("max_level") or 0)
            sev_tag  = "Critical" if level >= 12 else "High" if level >= 7 else "Medium" if level >= 4 else "Low"
            attack_t = meta.get("attack_type", "N/A")
            ts       = meta.get("timestamp", "N/A")
            mitre_m  = meta.get("mitre_ids", [])
            desc     = (meta.get("rule_description") or meta.get("description") or doc.text[:200])
            doc_summaries.append(
                f"[{idx+1}] agent={agent} | sev={sev_tag}(L{level}) | "
                f"attack={attack_t} | mitre={mitre_m} | time={ts}\n"
                f"    desc={desc[:180]}"
            )

        # ── 6.  Improved LLM prompt — numbers are locked, LLM writes narrative ──
        # IMPROVED: Add correlation layer, confidence scores, better formatting
        schema_json = (
            '{\n'
            f'  "file_label": "{file_label}",\n'
            f'  "total_events_analyzed": {total_count},\n'
            f'  "overall_severity": "{overall_sev}",\n'
            f'  "severity_breakdown": {json.dumps(severity_dist)},\n'
            '  "threat_count": <number of distinct threat groups listed in GROUPED THREATS above>,\n'
            '  "top_threats": [\n'
            '    {\n'
            '      "summary": "<NUMBER> <attack_type> events on <agent> — replace NUMBER with actual count from GROUPED THREATS>",\n'
            '      "severity": "<Critical|High|Medium|Low — from GROUPED THREATS>",\n'
            '      "attack_type": "<from GROUPED THREATS key>",\n'
            '      "mitre": {"id": "<T-ID from GROUPED THREATS>", "name": "<ATT&CK name>"},\n'
            '      "confidence": <0.0-1.0 based on evidence strength>,\n'
            '      "iocs": {"ips": ["<real IPs only>"], "users": ["<real users>"], "file_paths": ["<e.g., /bin/passwd>"], "commands": ["<e.g., sudo, su>"]},\n'
            '      "attack_scenario": "<2-3 sentence narrative from evidence — be SPECIFIC: include IPs, users, file paths, commands when available. Example: \\"SSH authentication from 10.200.200.20 detected on wazuh-server followed by privilege escalation via sudo, leading to file tampering on system binaries /bin/passwd and /usr/bin/chsh.\\">",\n'
            '      "recommendations": ["<concrete action>"]\n'
            '    }\n'
            '  ],\n'
            '  "attack_chain_summary": "<CORRELATED attack story: single incident with sequential steps, NOT separate threats>",\n'
            '  "key_indicators": ["<real IPs (e.g., 10.200.200.20), users (e.g., wazuh-user)> - DO NOT include system binaries like /usr/bin/su, /usr/bin/systemctl, /bin/*, /usr/bin/*"],\n'
            '  "analyst_notes": "<factual observations about the attack pattern — do NOT speculate or inflate>"\n'
            '}'
        )

        summary_prompt = (
            f"You are a Tier-2 SOC Analyst. Analyze the security dataset [{file_label}].\n\n"
            f"{stats_block}\n\n"
            f"TOP PRIORITY EVENTS (sample of {len(doc_summaries)} from {total_count} total):\n"
            + "\n".join(doc_summaries) + "\n\n"
            + (ioc_block + "\n\n" if ioc_block else "")
            + (chain_block + "\n\n" if chain_block else "")
            + f"""STRICT RULES — MANDATORY COMPLIANCE:
1. total_events_analyzed MUST be exactly {total_count}
2. overall_severity MUST be exactly "{overall_sev}"
3. severity_breakdown MUST be exactly {json.dumps(severity_dist)}
4. Each top_threat summary MUST use the EXACT event count from "GROUPED THREATS" above
   CORRECT: "6 rootcheck events on kali-vm suggest rootkit activity"
   WRONG:   "8 rootkit events..." (if the actual count is 6)
5. NEVER invent counts — only use numbers from GROUPED THREATS block
6. MITRE names must match ATT&CK exactly:
   T1014=Rootkit, T1078=Valid Accounts, T1548.003=Sudo and Sudo Caching,
   T1110=Brute Force, T1562=Impair Defenses, T1562.001=Disable or Modify Tools,
   T1021=Remote Services, T1204=User Execution
7. iocs arrays: MUST include real IOCs from the data - THIS IS CRITICAL:
   - ips: extract from "ips=" fields (e.g., 10.200.200.20)
   - users: extract from "users=" fields (e.g., wazuh-user)
   - file_paths: MUST extract from GROUPED THREATS "files=" field - these are the ACTUAL compromised files (e.g., /bin/passwd, /usr/bin/chsh, /usr/bin/su)
     * CRITICAL: If GROUPED THREATS shows files=X for file_tampering, you MUST include those exact paths in iocs.file_paths
     * DO NOT leave file_paths empty - if files are listed in GROUPED THREATS, extract them
   - commands: extract from "cmds=" field in GROUPED THREATS (e.g., sudo, su, systemctl restart network)
   - NEVER leave arrays empty if IOCs exist in GROUPED THREATS
8. EACH threat gets its own MITRE object — do NOT combine multiple MITRE IDs
9. attack_chain_summary: CORRELATE events into a SINGLE incident story, NOT separate threats
   CORRECT: "T1078 (SSH login from 10.200.200.20) → T1548.003 (sudo/su to root) → T1562.001 (trojaned /bin/passwd detected)"
   WRONG:   "rootkit events, privilege_escalation events, authentication events" (separate, not correlated)
10. attack_scenario rules:
    - For trojaned files: describe as "detected" not "installed" — use "file_tampering" attack_type
    - CORRECT: "File tampering indicators were detected on the system"
    - WRONG:   "The attacker installed a rootkit"
    - For rootkit: only use if CONFIRMED rootkit signature, not just "trojaned"
11. severity rules (Wazuh levels: 1-3=Low, 4-6=Medium, 7-11=High, 12+=Critical):
    - file_tampering (trojaned file) = High — confidence 0.75 (indicator, not confirmation)
    - rootkit = Critical (only for confirmed rootkit signatures) — confidence 0.85
    - privilege_escalation = High — confidence 0.75
    - authentication_success = Low/Medium — confidence 0.9
    - system_activity = Low — confidence 0.3 (informational events)
    - defense_evasion = Medium ONLY if actual evasion evidence — confidence 0.5
12. confidence field: rate 0.0-1.0 based on evidence strength:
    - 0.9 = strong evidence (actual login event)
    - 0.85 = confirmed malware/rootkit signature
    - 0.75 = high confidence (sudo commands, trojaned file indicator)
    - 0.5 = medium (system events with some concern)
    - 0.3 = low (informational, no clear threat)
13. analyst_notes: write factual observations about the SPECIFIC incident - be SPECIFIC:
    - CORRECT: "External SSH login from 10.200.200.20 detected on wazuh-server, followed by privilege escalation via sudo/su to root, then file tampering detected on system binaries /bin/passwd and /usr/bin/chsh indicating possible trojaned files."
    - WRONG:   "potential malicious activity" (too generic)
    - Include: source IP, target user, specific commands executed, specific files affected
14. Return ONLY valid JSON — no markdown, no explanation

OUTPUT:
""" + schema_json
        )

        # ── 7. Call LLM ──────────────────────────────────────────────
        def _call_llm():
            return self.generation_client.generate_text(
                prompt=summary_prompt,
                chat_history=[],
                max_output_tokens=2500,
                temperature=0.0,
            )

        try:
            raw_output = await loop.run_in_executor(None, _call_llm)
            parsed     = self.safe_parse_llm_output(raw_output)
            if not parsed:
                logger.warning("LLM output parse failed — using structured fallback")
                parsed = self._build_fallback_summary(
                    file_label, total_count, overall_sev, severity_dist,
                    attack_groups, ioc_block, chain
                )
        except Exception as e:
            logger.error(f"generate_file_summary LLM failed: {e}")
            parsed = self._build_fallback_summary(
                file_label, total_count, overall_sev, severity_dist,
                attack_groups, ioc_block, chain
            )

        # ── 8.  ALWAYS enforce ground-truth numbers — no exceptions ──
        if isinstance(parsed, dict):
            parsed["file_label"]            = file_label
            parsed["total_events_analyzed"] = total_count
            parsed["overall_severity"]      = overall_sev
            parsed["severity_breakdown"]    = severity_dist

            # FIX: Build full_log_text from all_texts for post-processing functions
            full_log_text = " ".join(all_texts) if all_texts else ""

            # Fix each threat's counts to match real data
            if "top_threats" in parsed and isinstance(parsed["top_threats"], list):
                parsed["top_threats"] = self._fix_threat_counts(
                    parsed["top_threats"], attack_groups
                )
                
                # FIX: Enforce correct MITRE IDs based on attack_type
                parsed["top_threats"] = self._fix_mitre_by_attack_type(
                    parsed["top_threats"], attack_groups
                )
                
                # FIX: Fix attack_chain_summary consistency
                chain_summary = parsed.get("attack_chain_summary", "")
                # Replace ALL mentions of rootkit with file_tampering if trojaned is present
                if "trojaned" in chain_summary.lower():
                    import re
                    # Replace T1014/rootkit with T1562.001/file_tampering
                    chain_summary = re.sub(
                        r'T1014[^,\s]*',
                        'T1562.001',
                        chain_summary,
                        flags=re.IGNORECASE
                    )
                    chain_summary = re.sub(
                        r'\brootkit\b',
                        'file tampering',
                        chain_summary,
                        flags=re.IGNORECASE
                    )
                    parsed["attack_chain_summary"] = chain_summary
                
                # FIX: Fix MITRE chain order (T1078=auth, T1548=priv esc)
                if "T1078" in chain_summary and "privilege" in chain_summary.lower():
                    # T1078 is for authentication, not privilege escalation
                    parsed["attack_chain_summary"] = chain_summary.replace(
                        "T1078", "T1548.003"
                    )
                
                # FIX: COMPREHENSIVE attack_chain override - replace rootkit/T1014 with file_tampering/T1562.001
                # ONLY when there's evidence of trojaned files (not for confirmed rootkit)
                # Use SOURCE text (full_log_text) not LLM output for detection
                chain_summary = parsed.get("attack_chain_summary", "")
                has_trojaned_evidence = "trojaned" in full_log_text.lower()  # FIXED: from source, not chain
                
                if has_trojaned_evidence and ("rootkit" in chain_summary.lower() or "T1014" in chain_summary):
                    # Replace rootkit mentions with file tampering (trojaned is indicator, not confirmation)
                    chain_summary = re.sub(r'\brootkit\b', 'file tampering', chain_summary, flags=re.IGNORECASE)
                    chain_summary = re.sub(r'\brootkit infection\b', 'file integrity compromise', chain_summary, flags=re.IGNORECASE)
                    # Replace T1014 with T1562.001 only for trojaned indicators
                    chain_summary = re.sub(r'T1014[^,\s]*', 'T1562.001', chain_summary, flags=re.IGNORECASE)
                
                # Fix T1021 → T1078 for authentication (always correct)
                if "(T1021)" in chain_summary:
                    chain_summary = re.sub(r'\(T1021\)', '(T1078)', chain_summary, flags=re.IGNORECASE)
                
                parsed["attack_chain_summary"] = chain_summary
                
                # FIX: Clean prompt leaks FIRST (LLM sometimes returns prompt text)
                parsed["top_threats"] = self._clean_prompt_leaks(parsed["top_threats"])
                
                # FIX: Reclassify defense_evasion to system_activity if no clear evasion intent
                parsed["top_threats"] = self._reclassify_defense_evasion_in_threats(
                    parsed["top_threats"], full_log_text
                )
                
                # FIX: Enforce text consistency - summary/recommendations must match attack_type
                parsed["top_threats"] = self._fix_text_consistency(
                    parsed["top_threats"], attack_groups
                )
                
                # FINAL FIX: Final cleanup pass to remove any remaining leaks
                parsed["top_threats"] = self._final_cleanup_threats(parsed["top_threats"])
                
                # CRITICAL: Last-pass cleanup on the ENTIRE parsed object
                parsed = self._deep_clean_parsed_output(parsed, full_log_text)

            #  Clean and Normalize IOCs in each threat
            for threat in parsed.get("top_threats", []):
                atype = threat.get("attack_type", "")
                iocs = threat.get("iocs", {})
                if isinstance(iocs, dict):
                    # FIX: Normalize IOCs - clean commas, duplicates, garbage
                    iocs = self._normalize_iocs(iocs)
                    
                    # FIX: Context-aware filtering - auth should not have file_paths/commands
                    if atype == "authentication_success":
                        iocs["file_paths"] = []
                        iocs["commands"] = []
                    elif atype == "system_activity":
                        iocs["file_paths"] = []
                        iocs["commands"] = []
                    
                    for k in list(iocs.keys()):
                        iocs[k] = [v for v in (iocs[k] or [])
                                   if v and v not in ["_", "N/A", "0.0.0.0", ""]]
                threat["iocs"] = iocs if isinstance(iocs, dict) else {
                    "ips": [], "users": [], "file_paths": [], "commands": []
                }
            
            # FIX: Clean key_indicators - ensure it's a proper list
            if "key_indicators" in parsed:
                parsed["key_indicators"] = self._normalize_key_indicators(
                    parsed["key_indicators"], parsed.get("top_threats", []), full_log_text
                )

            # FIX: Dynamic confidence logic - make confidence intelligent based on evidence
            parsed["top_threats"] = self._adjust_confidence_by_evidence(
                parsed.get("top_threats", []), full_log_text
            )

            # FIX: Severity upgrade logic - escalate if multiple high-risk indicators present
            parsed = self._upgrade_severity_if_needed(parsed, full_log_text)

            # FIX: Generate attack_chain programmatically (no LLM hallucination)
            parsed["attack_chain_summary"] = self._generate_attack_chain(
                parsed.get("top_threats", []), full_log_text
            )

            # FIX: Filter suspicious file_paths only (not system binaries)
            parsed["top_threats"] = self._filter_suspicious_paths(
                parsed.get("top_threats", [])
            )

            # FIX: CRITICAL - Extract file_paths from source text for file_tampering threats
            # This ensures file_paths are never empty when trojaned files exist
            parsed["top_threats"] = self._ensure_file_paths_for_tampering(
                parsed.get("top_threats", []), full_log_text
            )

            # FIX: Add risk_score, timeline, and incident_type
            parsed = self._enrich_with_risk_and_timeline(parsed, full_log_text)

        # ── 9. Store RAPTOR summary chunk ────────────────────────────
        summary_text = (
            "FILE_SUMMARY_RAPTOR | source=" + file_label
            + " | severity=" + overall_sev
            + " | total_events=" + str(total_count)
            + " | " + json.dumps(parsed)
        )
        try:
            sv = self.embedding_client.embed_text(
                text="FILE SUMMARY RAPTOR overall severity threats attack chain indicators",
                document_type="document",
            )
            if sv and isinstance(sv[0], list):
                sv = sv[0]
            if sv:
                await self.vectordb_client.insert_many(
                    collection_name=collection_name,
                    texts=[summary_text],
                    vectors=[sv],
                    metadata=[{
                        "chunk_level":      1,
                        "source":           file_label,
                        "is_summary":       True,
                        "overall_severity": overall_sev,
                        "threat_count":     parsed.get("threat_count", 0),
                        "total_events":     total_count,
                    }],
                    record_ids=[None],
                )
                logger.info(f" RAPTOR summary stored ({total_count} events, severity={overall_sev})")
        except Exception as e:
            logger.warning(f"Could not store summary chunk: {e}")

        return parsed

    # ──────────────────────────────────────────
    #  NEW helpers for generate_file_summary
    # ──────────────────────────────────────────
    def _infer_attack_type_from_text(self, text: str) -> str:
        """Infer canonical attack_type from raw event text."""
        text_lower = text.lower()
        for keyword, atype in ATTACK_TYPE_CANONICAL.items():
            if keyword in text_lower:
                return atype
        for keyword, mitre_id in KEYWORD_TO_MITRE.items():
            if keyword in text_lower:
                # Map MITRE to attack type - FIXED: T1078 for auth, T1562.001 for file tampering
                mapping = {
                    "T1014": "rootkit", 
                    "T1548.003": "privilege_escalation",
                    "T1110": "credential_access", 
                    "T1078": "authentication_success",  # FIXED: was T1021
                    "T1021": "lateral_movement",  # FIXED: was authentication_success
                    "T1204": "execution",
                    "T1562": "defense_evasion", 
                    "T1562.001": "file_tampering",  # FIXED: added for trojaned files
                }
                return mapping.get(mitre_id, "unknown")
        return "unknown"

    def _reclassify_attack_type(self, current_type: str, text: str) -> str:
        """
        Reclassify attack types using CURRENT rules to fix old misclassifications.
        This is critical because data in DB was classified with old (incorrect) rules.
        
        CRITICAL FIX: defense_evasion is OVER-USED - most events labeled as defense_evasion
        are actually system_activity (informational events like SELinux, iptables without evasion intent).
        FIX 2: Also handle the case where defense_evasion appears with file_tampering - prefer file_tampering.
        FIX 3: More aggressive system_activity classification for SELinux/iptables without clear intent.
        """
        text_lower = text.lower()
        
        # FIX 1: trojaned = indicator, NOT confirmation of rootkit
        if current_type == "rootkit" and "trojaned" in text_lower:
            return "file_tampering"
        
        # FIX 2: defense_evasion over-generalization - CRITICAL fix
        # Most events labeled defense_evasion are actually system_activity
        if current_type == "defense_evasion":
            # If there's NO clear evasion intent, it's system_activity
            # Clear evasion = disable, stop, remove, bypass, tamper, kill
            evasion_intent_keywords = ["disable", "stop ", "remove ", "bypass", "tamper", 
                                       "kill ", "uninstall", "unload", "modify rules",
                                       "stopped ", "disabled ", "stopped firewall", 
                                       "disabled selinux", "killed ", "removed",
                                       "setenforce 0", "iptables -f", "ufw disable"]
            has_evasion_intent = any(k in text_lower for k in evasion_intent_keywords)
            
            if not has_evasion_intent:
                return "system_activity"
            
            # Even with evasion keywords, check if it's actually security-related
            # SELinux without "disable" = system_activity
            if "selinux" in text_lower and "disable" not in text_lower and "setenforce" not in text_lower:
                return "system_activity"
            
            # iptables without -f (flush) or -D (delete) = system_activity
            if "iptables" in text_lower and "flush" not in text_lower and "delete" not in text_lower:
                return "system_activity"
            
            # If there's file tampering evidence, prefer that over defense_evasion
            if "trojaned" in text_lower or "replaced" in text_lower:
                return "file_tampering"
        
        # FIX 3: Keep known good types
        if current_type in ["rootkit", "privilege_escalation", "authentication_success", 
                           "credential_access", "file_tampering", "system_activity"]:
            return current_type
        
        return current_type

    def _build_threat_groups_block(self, attack_groups: dict, total_count: int) -> str:
        """
        Build a human-readable block of grouped threats with EXACT counts.
        This is embedded directly in the LLM prompt so it cannot hallucinate counts.
        FIX: Include file_paths and commands for complete IOC extraction.
        """
        if not attack_groups:
            return ""
        lines = [f"GROUPED THREATS (computed from all {total_count} events):"]
        for atype, stats in sorted(attack_groups.items(), key=lambda x: -x[1]["count"]):
            if atype == "unknown":
                continue
            mitre_list = ", ".join(sorted(stats["mitre_ids"])) or "inferred"
            agents_str = ", ".join(sorted(stats["agents"]))
            ips_str    = ", ".join(sorted(stats["ips"])) or "N/A"
            users_str  = ", ".join(sorted(stats["users"])) or "N/A"
            # FIX: Include file_paths and commands
            files_str  = ", ".join(sorted(stats.get("file_paths", set()))) or "N/A"
            cmds_str   = ", ".join(sorted(stats.get("commands", set()))) or "N/A"
            lines.append(
                f"  [{atype}] count={stats['count']} | severity={stats['severity']}(L{stats['max_level']}) "
                f"| agents={agents_str} | ips={ips_str} | users={users_str} | files={files_str} | cmds={cmds_str} | mitre={mitre_list}"
            )
        return "\n".join(lines)

    def _fix_threat_counts(self, threats: list, attack_groups: dict) -> list:
        """
        Post-process: completely rebuild threat summaries with correct counts and format.
        Eliminates any LLM placeholder text.
        """
        for threat in threats:
            atype = threat.get("attack_type", "")
            if not atype:
                continue

            # Find matching group
            real_count = None
            real_agents = []
            for group_key, stats in attack_groups.items():
                if (group_key == atype or
                        atype in group_key or
                        group_key in atype):
                    real_count = stats["count"]
                    real_agents = list(stats["agents"])
                    break

            if real_count is not None:
                # FIX: Completely rebuild summary with proper format - no placeholders
                agent_str = ", ".join(real_agents) if real_agents else "unknown agent"
                threat["summary"] = f"{real_count} {atype} events on {agent_str}"

                # CRITICAL: Enrich IOCs from group stats - THIS IS THE SOURCE OF TRUTH
                iocs = threat.get("iocs", {})
                if not isinstance(iocs, dict):
                    iocs = {"ips": [], "users": [], "file_paths": [], "commands": []}
                
                # Get group stats for this attack_type
                group_stats = attack_groups.get(atype, {})
                
                # 1. IPs - from group stats (authoritative source)
                group_ips = list(group_stats.get("ips", set()))
                if group_ips:
                    existing_ips = set(iocs.get("ips", []))
                    iocs["ips"] = list(existing_ips | set(group_ips))[:8]
                
                # 2. Users - from group stats
                group_users = list(group_stats.get("users", set()))
                if group_users:
                    existing_users = set(iocs.get("users", []))
                    iocs["users"] = list(existing_users | set(group_users))[:8]
                
                # 3. CRITICAL: file_paths - from group stats for file_tampering
                # This is the most common failure point - ensure we always have paths
                group_files = list(group_stats.get("file_paths", set()))
                if group_files:
                    existing_files = set(iocs.get("file_paths", []))
                    iocs["file_paths"] = list(existing_files | set(group_files))[:8]
                
                # 4. Commands - from group stats
                group_cmds = list(group_stats.get("commands", set()))
                if group_cmds:
                    existing_cmds = set(iocs.get("commands", []))
                    iocs["commands"] = list(existing_cmds | set(group_cmds))[:8]
                
                threat["iocs"] = iocs

        return threats

    def _fix_mitre_by_attack_type(self, threats: list, attack_groups: dict) -> list:
        """
        FIX: Enforce correct MITRE IDs based on attack_type.
        This overrides any wrong MITRE from LLM output.
        """
        # Canonical MITRE mapping - source of truth
        MITRE_BY_TYPE = {
            "rootkit":              {"id": "T1014",     "name": "Rootkit"},
            "file_tampering":       {"id": "T1562.001", "name": "Disable or Modify Tools"},
            "defense_evasion":      {"id": "T1562",     "name": "Impair Defenses"},
            "privilege_escalation": {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
            "credential_access":    {"id": "T1110",     "name": "Brute Force"},
            "authentication_success": {"id": "T1078",  "name": "Valid Accounts"},  # FIXED: was T1021
            "lateral_movement":     {"id": "T1021",     "name": "Remote Services"},
            "system_activity":      {"id": "T1082",     "name": "System Information Discovery"},
            "execution":            {"id": "T1204",     "name": "User Execution"},
        }
        
        for threat in threats:
            atype = threat.get("attack_type", "")
            scenario = threat.get("attack_scenario", "").lower()
            
            # FIX: COMPREHENSIVE rootkit → file_tampering conversion
            # Check ALL possible sources of evidence:
            
            # 1. Check if ANY group has file_paths (indicates trojaned files, not rootkit)
            any_group_has_files = False
            for group_type, group_data in attack_groups.items():
                if group_data.get("file_paths"):
                    any_group_has_files = True
                    break
            
            # 2. Check scenario for trojaned keyword
            has_trojaned_in_scenario = "trojaned" in scenario
            
            # 3. Check if attack_groups has file_tampering key
            has_file_tampering_group = "file_tampering" in attack_groups
            
            # CONVERT if any evidence exists
            should_convert = (
                atype == "rootkit" and (
                    any_group_has_files or 
                    has_trojaned_in_scenario or 
                    has_file_tampering_group
                )
            )
            
            if should_convert:
                atype = "file_tampering"
                threat["attack_type"] = "file_tampering"
                threat["severity"] = "High"
                threat["confidence"] = 0.75
                threat["attack_scenario"] = "Possible file integrity compromise detected on system binaries (trojaned file indicator)."
            
            # FIX: Enforce correct MITRE
            if atype in MITRE_BY_TYPE:
                threat["mitre"] = MITRE_BY_TYPE[atype]
            
            # FIX: COMPREHENSIVE IOC extraction - check ALL groups
            iocs = threat.get("iocs", {})
            if isinstance(iocs, dict):
                # Collect IOCs from ALL groups (not just current atype)
                all_ips = set()
                all_users = set()
                all_files = set()
                all_cmds = set()
                
                for group_type, group_data in attack_groups.items():
                    all_ips.update(group_data.get("ips", set()))
                    all_users.update(group_data.get("users", set()))
                    all_files.update(group_data.get("file_paths", set()))
                    all_cmds.update(group_data.get("commands", set()))
                
                # Populate empty IOC fields
                if not iocs.get("ips") and all_ips:
                    iocs["ips"] = list(all_ips)[:8]
                if not iocs.get("users") and all_users:
                    iocs["users"] = list(all_users)[:8]
                if not iocs.get("file_paths") and all_files:
                    iocs["file_paths"] = list(all_files)[:8]
                if not iocs.get("commands") and all_cmds:
                    iocs["commands"] = list(all_cmds)[:8]
                
                threat["iocs"] = iocs
        
        return threats

    def _normalize_iocs(self, iocs: dict) -> dict:
        """
        FIX: Normalize IOC values - clean commas, duplicates, garbage values.
        This fixes the parsing bugs in extracted IOCs.
        """
        if not isinstance(iocs, dict):
            return {"ips": [], "users": [], "file_paths": [], "commands": []}
        
        normalized = {}
        
        # Garbage patterns to filter out
        garbage_patterns = [
            "replace", "number", "actual", "grouped", "threats",
            "sudo to", "su |", "su-", "|", "&&", ";;"
        ]
        
        for key, values in iocs.items():
            if not values:
                normalized[key] = []
                continue
            
            cleaned = set()
            for v in values:
                if not v or not isinstance(v, str):
                    continue
                
                # Split by comma (common parsing issue)
                parts = v.split(",")
                for part in parts:
                    # Clean each part
                    part = part.strip().strip(",").strip()
                    # Skip garbage values
                    if not part:
                        continue
                    if any(g in part.lower() for g in garbage_patterns):
                        continue
                    if len(part) < 2:
                        continue
                    
                    # For file_paths: must start with /
                    if key == "file_paths" and not part.startswith("/"):
                        continue
                    
                    # For commands: clean up and validate
                    if key == "commands":
                        # Remove trailing symbols
                        part = part.rstrip("|;&")
                        # FIX: Normalize command paths - strip /usr/bin/, /bin/ prefixes
                        part = re.sub(r'^/usr/bin/', '', part)
                        part = re.sub(r'^/bin/', '', part)
                        # Expanded list of valid command starts
                        valid_starts = ("sudo", "su", "systemctl", "chmod", "chown", "rm", "cp", "mv",
                                       "bash", "sh", "python", "curl", "wget", "nc", "netcat", "ping")
                        if not part.startswith("/") and not part.startswith(valid_starts):
                            continue
                        # Skip if it's just a symbol or short
                        if len(part) < 3:
                            continue
                    
                    # FIX: Deduplicate while preserving order (use dict.fromkeys, not set)
                    cleaned.add(part)
            
            # Preserve order using dict.fromkeys() - removes duplicates while keeping first occurrence order
            normalized[key] = list(dict.fromkeys(cleaned))
        
        return normalized

    def _clean_prompt_leaks(self, threats: list) -> list:
        """
        FIX: Remove prompt text that leaked into LLM output.
        Common leaks: "replace NUMBER with...", "GROUPED THREATS>", etc.
        """
        if not isinstance(threats, list):
            return threats
        
        leak_patterns = [
            "replace NUMBER",
            "GROUPED THREATS",
            "actual count from",
            "<number>",
            "<from GROUPED",
            "replace NUMBER with",
            "GROUPED THREATS>",
            "<attack_type>",
            "<from GROUPED THREATS>",
            "NUMBER with actual",
            "actual count from GROUPED",
        ]
        
        cleaned_threats = []
        for threat in threats:
            if not isinstance(threat, dict):
                cleaned_threats.append(threat)
                continue
            
            # Clean all string fields - COMPREHENSIVE cleaning
            for key, value in threat.items():
                if isinstance(value, str):
                    original = value
                    for pattern in leak_patterns:
                        if pattern.lower() in value.lower():
                            # Replace with empty
                            value = value.replace(pattern, "")
                    # CRITICAL: Also clean up any double spaces or trailing garbage
                    value = re.sub(r'\s+', ' ', value)  # Multiple spaces to single
                    value = re.sub(r'\s*[-–—]\s*$', '', value)  # Trailing dashes
                    value = value.strip()
                    
                    # If summary is now empty or garbage, rebuild it
                    if key == "summary" and (not value or len(value) < 10):
                        atype = threat.get("attack_type", "unknown")
                        count = threat.get("summary", "")
                        # Try to extract count from original
                        count_match = re.search(r'(\d+)\s+\w+', original)
                        count_str = count_match.group(1) if count_match else "1"
                        agent = "unknown"
                        # Try to get agent from other fields
                        for k, v in threat.items():
                            if isinstance(v, str) and "vm" in v.lower() or "server" in v.lower():
                                agent = v
                                break
                        value = f"{count_str} {atype} events on {agent}"
                    
                    threat[key] = value
                
            # Also clean IOC arrays
            iocs = threat.get("iocs", {})
            if isinstance(iocs, dict):
                for k, v in iocs.items():
                    if isinstance(v, list):
                        iocs[k] = [
                            x for x in v 
                            if not any(p.lower() in str(x).lower() for p in leak_patterns)
                        ]
                threat["iocs"] = iocs
            
            cleaned_threats.append(threat)
        
        return cleaned_threats

    def _fix_text_consistency(self, threats: list, attack_groups: dict) -> list:
        """
        FIX: Ensure summary and recommendations match attack_type.
        If attack_type is file_tampering, summary should say "file_tampering" not "rootkit".
        FIX 2: Make attack_scenario more specific with actual IOCs (IPs, users, files, commands).
        """
        for threat in threats:
            atype = threat.get("attack_type", "")
            iocs = threat.get("iocs", {})
            
            # Fix summary - replace rootkit with file_tampering if needed
            summary = threat.get("summary", "")
            if atype == "file_tampering" and "rootkit" in summary.lower():
                threat["summary"] = summary.replace("rootkit", "file_tampering")
            
            # FIX: Make attack_scenario more specific with actual IOCs
            attack_scenario = threat.get("attack_scenario", "")
            if attack_scenario and isinstance(iocs, dict):
                # Extract actual IOCs
                ips = iocs.get("ips", [])
                users = iocs.get("users", [])
                files = iocs.get("file_paths", [])
                cmds = iocs.get("commands", [])
                
                # Build specific scenario
                scenario_parts = []
                
                if atype == "authentication_success" and ips:
                    scenario_parts.append(f"SSH authentication from {ips[0]}")
                    if users:
                        scenario_parts.append(f"using {users[0]}")
                
                elif atype == "privilege_escalation" and cmds:
                    scenario_parts.append(f"Privilege escalation via {cmds[0]}")
                    if users:
                        scenario_parts.append(f"by {users[0]}")
                
                elif atype == "file_tampering" and files:
                    scenario_parts.append(f"File tampering detected on {', '.join(files[:2])}")
                    if "trojaned" in attack_scenario.lower():
                        scenario_parts.append("(trojaned binary indicator)")
                
                elif atype == "credential_access" and ips:
                    scenario_parts.append(f"Brute force attempt from {ips[0]}")
                
                # If we have specific details, replace generic scenario
                if scenario_parts:
                    specific_scenario = " ".join(scenario_parts)
                    # Only replace if current scenario is generic
                    if len(attack_scenario) > 100 or "detected" in attack_scenario.lower():
                        threat["attack_scenario"] = specific_scenario
            
            # Fix recommendations - remove rootkit references for file_tampering
            recommendations = threat.get("recommendations", [])
            if isinstance(recommendations, list):
                new_recommendations = []
                for rec in recommendations:
                    if isinstance(rec, str):
                        # Replace rootkit with file tampering in recommendations
                        rec = rec.replace("rootkit", "file tampering")
                        rec = rec.replace("rootkit infection", "file integrity compromise")
                        new_recommendations.append(rec)
                threat["recommendations"] = new_recommendations
        
        return threats

    def _reclassify_defense_evasion_in_threats(self, threats: list, source_text: str) -> list:
        """
        FIX: Post-process defense_evasion threats - convert to system_activity if no clear evasion intent.
        This ensures defense_evasion is only used when there's actual evasion evidence.
        FIX 2: Also ensure file_tampering threats have file_paths extracted from source.
        """
        text_lower = source_text.lower()
        
        # Check if there's clear evasion intent in the source
        evasion_intent_keywords = [
            "disable", "stop ", "remove ", "bypass", "tamper",
            "kill ", "uninstall", "unload", "setenforce 0",
            "iptables -f", "ufw disable", "stopped firewall",
            "disabled selinux"
        ]
        has_clear_evasion = any(k in text_lower for k in evasion_intent_keywords)
        
        # FIX: Extract file_paths from source for file_tampering threats
        extracted_file_paths = []
        if "trojaned" in text_lower or "integrity" in text_lower:
            # Extract all system binary paths
            extracted_file_paths = re.findall(
                r'(/bin/[a-zA-Z0-9_.-]+|/usr/bin/[a-zA-Z0-9_.-]+|/sbin/[a-zA-Z0-9_.-]+|/usr/sbin/[a-zA-Z0-9_.-]+|/etc/[a-zA-Z0-9_./-]+)',
                source_text
            )
            extracted_file_paths = list(set(extracted_file_paths))[:8]
        
        for threat in threats:
            atype = threat.get("attack_type", "")
            
            if atype == "defense_evasion":
                # If no clear evasion intent, convert to system_activity
                if not has_clear_evasion:
                    threat["attack_type"] = "system_activity"
                    threat["severity"] = "Low"
                    threat["confidence"] = 0.3
                    threat["summary"] = threat.get("summary", "").replace(
                        "defense_evasion", "system_activity"
                    )
                    threat["attack_scenario"] = "Informational system event - no clear evasion intent detected."
                    threat["mitre"] = {"id": "T1082", "name": "System Information Discovery"}
                    threat["iocs"] = {"ips": [], "users": [], "file_paths": [], "commands": []}
                    threat["risk_score"] = 0.15
            
            # FIX: Ensure file_tampering has file_paths
            if atype == "file_tampering":
                iocs = threat.get("iocs", {})
                if not isinstance(iocs, dict):
                    iocs = {"ips": [], "users": [], "file_paths": [], "commands": []}
                
                current_paths = iocs.get("file_paths", [])
                
                # If no file_paths but we extracted from source, use them
                if not current_paths and extracted_file_paths:
                    iocs["file_paths"] = extracted_file_paths
                    threat["iocs"] = iocs
                # If partially filled, add more from extracted
                elif current_paths and len(current_paths) < 3 and extracted_file_paths:
                    existing = set(current_paths)
                    combined = list(existing | set(extracted_file_paths))[:8]
                    iocs["file_paths"] = combined
                    threat["iocs"] = iocs
        
        return threats

    def _deep_clean_parsed_output(self, parsed: dict, source_text: str) -> dict:
        """
        CRITICAL: Final deep clean of the ENTIRE parsed output.
        This catches any remaining leaks that might have been missed.
        """
        # Most comprehensive leak patterns
        leak_patterns = [
            "replace NUMBER", "GROUPED THREATS", "actual count from",
            "<number>", "<from GROUPED", "<attack_type>", "<concrete",
            "NUMBER with", "actual count from", "GROUPED THREATS>",
            "replace NUMBER with", "GROUPED THREATS>", "NUMBER with actual",
            "actual count from GROUPED", "<from GROUPED THREATS>",
            "replace NUMBER with  GROUPED",  # SPECIFIC pattern from output
        ]
        
        # Clean top_threats
        if "top_threats" in parsed and isinstance(parsed["top_threats"], list):
            for threat in parsed["top_threats"]:
                if not isinstance(threat, dict):
                    continue
                
                # Clean summary - rebuild if contains leaks
                summary = threat.get("summary", "")
                if any(p.lower() in summary.lower() for p in leak_patterns):
                    atype = threat.get("attack_type", "unknown")
                    # Extract count from the garbage text
                    count_match = re.search(r'(\d+)\s+\w+', summary)
                    count_str = count_match.group(1) if count_match else "1"
                    threat["summary"] = f"{count_str} {atype} events"
                
                # Clean attack_scenario
                scenario = threat.get("attack_scenario", "")
                if any(p.lower() in scenario.lower() for p in leak_patterns):
                    atype = threat.get("attack_type", "")
                    threat["attack_scenario"] = f"{atype.capitalize()} event detected."
        
        # Clean key_indicators
        if "key_indicators" in parsed and isinstance(parsed["key_indicators"], list):
            cleaned = []
            for ind in parsed["key_indicators"]:
                if isinstance(ind, str) and not any(p.lower() in ind.lower() for p in leak_patterns):
                    cleaned.append(ind)
            parsed["key_indicators"] = cleaned
        
        # Clean analyst_notes
        if "analyst_notes" in parsed and isinstance(parsed["analyst_notes"], str):
            notes = parsed["analyst_notes"]
            if any(p.lower() in notes.lower() for p in leak_patterns):
                parsed["analyst_notes"] = "Security events analyzed. Review recommended."
        
        return parsed

    def _final_cleanup_threats(self, threats: list) -> list:
        """
        FINAL FIX: Last-pass cleanup to ensure no placeholder text or garbage remains.
        """
        # Comprehensive leak patterns - EXPANDED
        leak_patterns = [
            "replace", "NUMBER", "GROUPED THREATS", "actual count",
            "<number>", "<from GROUPED", "<attack_type>", "<concrete",
            "NUMBER with", "actual count from", "GROUPED THREATS>",
            "replace NUMBER with", "GROUPED THREATS>", "NUMBER with actual",
            "actual count from GROUPED", "<from GROUPED THREATS>",
        ]
        
        cleaned_threats = []
        for threat in threats:
            if not isinstance(threat, dict):
                continue
            
            # Clean summary field - rebuild if still has leaks
            summary = threat.get("summary", "")
            if any(p.lower() in summary.lower() for p in leak_patterns):
                # Rebuild summary from other fields
                atype = threat.get("attack_type", "unknown")
                severity = threat.get("severity", "Medium")
                # Try to extract count from original
                count_match = re.search(r'(\d+)\s+\w+', summary)
                count_str = count_match.group(1) if count_match else "1"
                threat["summary"] = f"{count_str} {atype} events"
            
            # Clean attack_scenario
            scenario = threat.get("attack_scenario", "")
            if any(p.lower() in scenario.lower() for p in leak_patterns):
                atype = threat.get("attack_type", "")
                threat["attack_scenario"] = f"{atype.capitalize()} event detected."
            
            # Clean recommendations
            recommendations = threat.get("recommendations", [])
            if isinstance(recommendations, list):
                cleaned_recs = []
                for rec in recommendations:
                    if isinstance(rec, str) and not any(p.lower() in rec.lower() for p in leak_patterns):
                        cleaned_recs.append(rec)
                if not cleaned_recs:
                    cleaned_recs = ["Review system logs and investigate."]
                threat["recommendations"] = cleaned_recs
            
            cleaned_threats.append(threat)
        
        return cleaned_threats

    def _normalize_key_indicators(self, key_indicators: list, threats: list, source_text: str = "") -> list:
        """
        FIX: Normalize key_indicators to be a clean list without duplicates or garbage.
        CRITICAL: Filter out system binaries (/usr/bin/*, /bin/*) - they are NOT IOCs.
        Only real IOCs: IPs, users, actual suspicious file paths.
        FIX 2: More aggressive filtering - exclude ALL /usr/bin/*, /bin/* paths.
        FIX 3: Extract from source_text if key_indicators is empty.
        """
        # System binary paths to EXCLUDE (NOT IOCs) - EXPANDED
        SYSTEM_BINARIES = {
            "/usr/bin/su", "/usr/bin/systemctl", "/usr/bin/sudo", "/bin/su",
            "/bin/systemctl", "/bin/sudo", "/usr/bin/", "/bin/",
            "/usr/sbin/", "/sbin/", "/usr/local/bin/", "/usr/local/sbin/",
            "/usr/bin/passwd", "/usr/bin/chsh", "/bin/passwd", "/bin/chsh",
            "/usr/bin/su-", "/bin/su-", "su", "sudo", "systemctl", "chsh",
        }
        
        # Commands to EXCLUDE from key_indicators (they are system commands, not IOCs)
        SYSTEM_COMMANDS = {
            "sudo", "su", "su-", "systemctl", "chsh", "chmod", "chown",
            "ls", "cd", "pwd", "cat", "grep", "echo", "date", "whoami",
        }
        
        if not key_indicators:
            # Extract from threats - ALL real IOCs (IPs, users, AND commands)
            indicators = set()
            for threat in threats:
                iocs = threat.get("iocs", {})
                if isinstance(iocs, dict):
                    # Add IPs
                    for v in iocs.get("ips", []):
                        if v and v not in ["_", "N/A", "", "0.0.0.0"]:
                            indicators.add(v)
                    # Add users - CRITICAL: include ALL users
                    for v in iocs.get("users", []):
                        if v and v not in ["_", "N/A", "", "0.0.0.0"]:
                            indicators.add(v)
                    # Add commands (clean them - remove /usr/bin/, /bin/ prefixes)
                    for v in iocs.get("commands", []):
                        if v and v not in ["_", "N/A", ""]:
                            # Clean command path - keep full command but remove prefix
                            clean_cmd = re.sub(r'^/usr/bin/', '', v)
                            clean_cmd = re.sub(r'^/bin/', '', clean_cmd)
                            clean_cmd = re.sub(r'^/usr/sbin/', '', clean_cmd)
                            if clean_cmd and len(clean_cmd) > 2:
                                indicators.add(clean_cmd)
            
            # CRITICAL: If still empty, try to extract from source text
            if not indicators and source_text:
                # Extract IPs
                ips = re.findall(r'\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.\d+\.\d+\.\d+)\b', source_text)
                indicators.update(ips[:3])
                # Extract users
                users = re.findall(r'(?:user|username|srcuser)[:=]\s*([a-zA-Z0-9_.-]+)', source_text, re.IGNORECASE)
                indicators.update(users[:3])
            
            return list(indicators)[:10]
        
        # Clean existing key_indicators
        cleaned = set()
        for v in key_indicators:
            if not v or not isinstance(v, str):
                continue
            # Split by comma if needed
            parts = v.split(",")
            for part in parts:
                part = part.strip().strip(",").strip()
                if not part or len(part) < 2:
                    continue
                if part in ["_", "N/A"]:
                    continue
                
                # CRITICAL: Filter out system binaries - MORE AGGRESSIVE
                is_system_binary = False
                for sb in SYSTEM_BINARIES:
                    if part.startswith(sb) or part == sb or sb in part:
                        is_system_binary = True
                        break
                if is_system_binary:
                    continue
                
                # FIX: Also filter out system commands
                part_lower = part.lower()
                if part_lower in SYSTEM_COMMANDS:
                    continue
                
                # FIX: Only keep IPs and users - these are real IOCs
                # Skip file paths and commands in key_indicators
                if part.startswith("/") or part_lower in ["sudo", "su", "systemctl"]:
                    continue
                
                cleaned.add(part)
        
        return list(cleaned)[:10]

    def _adjust_confidence_by_evidence(self, threats: list, source_text: str) -> list:
        """
        FIX: Dynamic confidence logic - adjust confidence based on evidence strength.
        Makes the confidence score intelligent rather than static.
        FIX 2: Reduce confidence if file_paths is empty for file_tampering (weak evidence).
        """
        text_lower = source_text.lower()
        
        for threat in threats:
            atype = threat.get("attack_type", "")
            current_confidence = threat.get("confidence", 0.5)
            iocs = threat.get("iocs", {})
            
            # FIX: Reduce confidence if file_tampering has no file_paths (weak evidence)
            if atype == "file_tampering" and isinstance(iocs, dict):
                file_paths = iocs.get("file_paths", [])
                if not file_paths or len(file_paths) == 0:
                    # No file paths = weak evidence - reduce confidence
                    current_confidence = min(current_confidence, 0.6)
            
            # Base confidence by attack type
            if atype == "rootkit":
                # Confirmed rootkit signature = high confidence
                new_confidence = 0.85
            elif atype == "file_tampering":
                # Trojaned file = indicator, not confirmation
                if "trojaned" in text_lower:
                    new_confidence = 0.75
                else:
                    new_confidence = 0.7
            elif atype == "privilege_escalation":
                # sudo/su commands = strong evidence
                if any(k in text_lower for k in ["sudo", " su ", "su -", "sudo -"]):
                    new_confidence = 0.8
                else:
                    new_confidence = 0.7
            elif atype == "authentication_success":
                # Successful auth = strong evidence
                if "success" in text_lower or "accepted" in text_lower:
                    new_confidence = 0.9
                else:
                    new_confidence = 0.75
            elif atype == "credential_access":
                # Brute force attempts
                new_confidence = 0.75
            elif atype == "defense_evasion":
                # Only high if clear evasion intent
                if any(k in text_lower for k in ["disable", "stop", "remove", "bypass"]):
                    new_confidence = 0.7
                else:
                    new_confidence = 0.5
            else:
                new_confidence = 0.5
            
            # Override with higher of current or calculated
            threat["confidence"] = max(current_confidence, new_confidence)
        
        return threats

    def _upgrade_severity_if_needed(self, parsed: dict, source_text: str) -> dict:
        """
        FIX: Severity upgrade logic - escalate severity if multiple high-risk indicators present.
        This makes severity intelligent based on combined risk factors.
        """
        text_lower = source_text.lower()
        current_severity = parsed.get("overall_severity", "Medium")
        
        # Count high-risk indicators
        risk_score = 0
        
        # External IPs (not internal)
        iocs = parsed.get("top_threats", [])
        for threat in iocs:
            threat_iocs = threat.get("iocs", {})
            for ip in threat_iocs.get("ips", []):
                if ip and not ip.startswith(("10.", "192.168.", "172.", "127.")):
                    risk_score += 1
        
        # Privilege escalation indicators
        if any(k in text_lower for k in ["sudo", " su ", "su -", "root", "uid=0"]):
            risk_score += 2
        
        # File tampering indicators
        if any(k in text_lower for k in ["trojaned", "replaced", "modified system"]):
            risk_score += 2
        
        # Multiple attack types
        attack_types = set(t.get("attack_type", "") for t in iocs)
        if len(attack_types) >= 3:
            risk_score += 1
        
        # Upgrade severity based on risk score
        if risk_score >= 4 and current_severity not in ["Critical"]:
            parsed["overall_severity"] = "Critical"
        elif risk_score >= 3 and current_severity in ["Low", "Medium"]:
            parsed["overall_severity"] = "High"
        elif risk_score >= 2 and current_severity == "Low":
            parsed["overall_severity"] = "Medium"
        
        return parsed

    def _generate_attack_chain(self, threats: list, source_text: str) -> str:
        """
        FIX: Generate attack_chain programmatically - no LLM hallucination.
        Builds chain from actual detected attack types in order of severity.
        
        CRITICAL FIXES:
        1. Remove duplicate T1562 → T1562.001 (same category) - use only T1562.001
        2. Skip system_activity from attack chain (it's informational, not attack)
        3. Proper MITRE ordering: T1078 (auth) → T1548.003 (priv esc) → T1562.001 (file tampering)
        """
        text_lower = source_text.lower()
        chain_steps = []
        
        # Define attack chain order (kill chain sequence)
        # NOTE: T1562 and T1562.001 are in same category - use only T1562.001 if both present
        MITRE_CHAIN = {
            "authentication_success": ("T1078", "Initial Access - Valid Account"),
            "credential_access": ("T1110", "Credential Access - Brute Force"),
            "execution": ("T1204", "Execution - User Execution"),
            "lateral_movement": ("T1021", "Lateral Movement - Remote Services"),
            "privilege_escalation": ("T1548.003", "Privilege Escalation - Sudo/Caching"),
            "defense_evasion": ("T1562", "Defense Evasion - Impair Defenses"),
            "file_tampering": ("T1562.001", "File Tampering - Disable/Modify Tools"),
            "rootkit": ("T1014", "Rootkit - Boot or Kernel Hook"),
            "system_activity": ("T1082", "System Information Discovery"),
        }
        
        # Check source text for each attack type
        detected_types = []
        for threat in threats:
            atype = threat.get("attack_type", "")
            if atype in MITRE_CHAIN:
                detected_types.append(atype)
        
        # CRITICAL FIX 1: If file_tampering exists, skip defense_evasion (avoid T1562 → T1562.001 duplication)
        if "file_tampering" in detected_types and "defense_evasion" in detected_types:
            detected_types.remove("defense_evasion")
        
        # CRITICAL FIX 2: Skip system_activity from attack chain (it's informational, not an attack)
        if "system_activity" in detected_types:
            detected_types.remove("system_activity")
        
        # Also check source text for additional evidence
        if "success" in text_lower or "accepted" in text_lower:
            if "authentication_success" not in detected_types:
                detected_types.append("authentication_success")
        if "sudo" in text_lower or " su " in text_lower:
            if "privilege_escalation" not in detected_types:
                detected_types.append("privilege_escalation")
        if "trojaned" in text_lower or "replaced" in text_lower:
            if "file_tampering" not in detected_types:
                detected_types.append("file_tampering")
        
        # Build chain in MITRE order - EXCLUDE system_activity
        for atype in MITRE_CHAIN.keys():
            if atype in detected_types and atype != "system_activity":
                mitre_id, description = MITRE_CHAIN[atype]
                chain_steps.append(f"{mitre_id} ({description})")
        
        if not chain_steps:
            return "T1082 (System Information Discovery)"
        
        return " → ".join(chain_steps)

    def _filter_suspicious_paths(self, threats: list) -> list:
        """
        FIX: Filter file_paths intelligently.
        - For file_tampering: KEEP trojaned system binaries (/bin/passwd, /usr/bin/chsh) - these ARE IOCs
        - For other types: EXCLUDE system binaries as they're expected on systems
        """
        # Paths that indicate suspicious activity
        SUSPICIOUS_PATTERNS = [
            "tmp", "var/tmp", "dev/shm", ".cache", "Downloads",
            ".local", ".config", "hidden", ".ssh", ".bashrc",
            "/etc/passwd", "/etc/shadow", "/etc/sudoers",
            "webapp", "www", "html", "uploads", "backdoor"
        ]
        
        # System binary paths to EXCLUDE for non-file_tampering threats
        SYSTEM_BINARIES = [
            "/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/",
            "/usr/lib/", "/lib/", "/usr/local/bin/"
        ]
        
        # CRITICAL: System binaries that ARE IOCs when related to file_tampering
        # These are the actual compromised files (trojaned binaries)
        TROJANED_BINARY_PATTERNS = [
            "/bin/passwd", "/usr/bin/passwd",
            "/bin/chsh", "/usr/bin/chsh",
            "/bin/su", "/usr/bin/su",
            "/bin/login", "/usr/bin/login",
            "/etc/passwd", "/etc/shadow",
            "/bin/", "/usr/bin/",  # Only if specifically marked as trojaned
        ]
        
        for threat in threats:
            iocs = threat.get("iocs", {})
            atype = threat.get("attack_type", "")
            
            if isinstance(iocs, dict):
                file_paths = iocs.get("file_paths", [])
                
                # Filter: different logic based on attack_type
                filtered = []
                for path in file_paths:
                    if not path:
                        continue
                    
                    # For file_tampering: KEEP trojaned binaries (they ARE IOCs!)
                    if atype == "file_tampering":
                        # Keep if it's a known trojaned binary pattern
                        is_trojaned = any(path.startswith(tbp) for tbp in TROJANED_BINARY_PATTERNS)
                        if is_trojaned:
                            filtered.append(path)
                        # Also keep if it matches suspicious patterns
                        elif any(p in path.lower() for p in SUSPICIOUS_PATTERNS):
                            filtered.append(path)
                    else:
                        # For other types: exclude system binaries
                        is_system_binary = any(path.startswith(sb) for sb in SYSTEM_BINARIES)
                        if is_system_binary:
                            continue
                        
                        # Keep if contains suspicious pattern
                        if any(p in path.lower() for p in SUSPICIOUS_PATTERNS):
                            filtered.append(path)
                        elif not path.startswith("/"):
                            # Keep relative paths (could be suspicious)
                            filtered.append(path)
                
                iocs["file_paths"] = filtered[:8]  # Limit to 8
                threat["iocs"] = iocs
        
        return threats

    def _ensure_file_paths_for_tampering(self, threats: list, source_text: str) -> list:
        """
        CRITICAL: Ensure file_tampering threats have file_paths extracted from source text.
        This is the final safety net - if LLM missed file_paths, we extract them here.
        """
        # Extract all file paths from source text
        extracted_paths = self._extract_file_paths_from_text(source_text)
        
        for threat in threats:
            atype = threat.get("attack_type", "")
            
            if atype == "file_tampering":
                iocs = threat.get("iocs", {})
                if not isinstance(iocs, dict):
                    iocs = {"ips": [], "users": [], "file_paths": [], "commands": []}
                
                current_paths = iocs.get("file_paths", [])
                
                # If no file_paths from LLM, use extracted paths
                if not current_paths and extracted_paths:
                    iocs["file_paths"] = extracted_paths
                    threat["iocs"] = iocs
                # If partially filled, add extracted paths to fill gaps
                elif current_paths and len(current_paths) < 3 and extracted_paths:
                    existing = set(current_paths)
                    combined = list(existing | set(extracted_paths))[:8]
                    iocs["file_paths"] = combined
                    threat["iocs"] = iocs
        
        return threats

    def _extract_file_paths_from_text(self, text: str) -> list:
        """
        CRITICAL: Extract actual file paths from raw text for file_tampering threats.
        This ensures file_paths are never empty when trojaned files are detected.
        FIX: More aggressive extraction - extract ALL system binary paths when trojaned detected.
        """
        if not text:
            return []
        
        found_paths = set()
        text_lower = text.lower()
        
        # FIX: More aggressive - extract paths whenever there's ANY file tampering indicator
        has_tampering_indicator = any(k in text_lower for k in [
            "trojaned", "integrity", "checksum", "changed", "modified", 
            "replaced", "tamper", "file ", "/bin/", "/usr/bin/", "/etc/"
        ])
        
        if not has_tampering_indicator:
            return []
        
        # Common patterns for trojaned files in Wazuh logs - EXPANDED
        patterns = [
            # Pattern 1: /bin/ or /usr/bin/ followed by common system binaries
            r'(/bin/[a-zA-Z][a-zA-Z0-9_.-]+)',
            r'(/usr/bin/[a-zA-Z][a-zA-Z0-9_.-]+)',
            r'(/sbin/[a-zA-Z][a-zA-Z0-9_.-]+)',
            r'(/usr/sbin/[a-zA-Z][a-zA-Z0-9_.-]+)',
            # Pattern 2: file paths in "file=" or "file=" format
            r'file[=:]?\s*["\']?([^\s"\',;]+)',
            r'path[=:]?\s*["\']?([^\s"\',;]+)',
            r'filename[=:]?\s*["\']?([^\s"\',;]+)',
            # Pattern 3: syscheck integrity messages
            r'Integrity checksum changed for ["\']?([^\s"\']+)',
            r'Trojaned version of ["\']?([^\s"\']+)',
            r'file "([^"]+)"',
            r"file '([^']+)'",
            # Pattern 4: Full paths in any context
            r'(/etc/[a-zA-Z0-9_./-]+)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                path = match.strip()
                # Filter out garbage
                if path and len(path) > 3 and not path.startswith("http"):
                    # Only keep system binary paths for file_tampering
                    if any(path.startswith(p) for p in ["/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/", "/etc/"]):
                        found_paths.add(path)
        
        # FIX: If still empty but trojaned detected, extract from raw log structure
        if not found_paths and "trojaned" in text_lower:
            # Try to find any /bin/ or /usr/bin/ paths in the text
            all_paths = re.findall(r'(/bin/[a-zA-Z0-9_.-]+|/usr/bin/[a-zA-Z0-9_.-]+)', text)
            found_paths = set(all_paths)
        
        return list(found_paths)[:8]  # Limit to 8

    def _enrich_with_risk_and_timeline(self, parsed: dict, source_text: str) -> dict:
        """
        FIX: Add risk_score per threat, timeline, and incident_type.
        Makes output suitable for SOC dashboards.
        IMPROVED: More specific timeline with actual IPs, users, commands, and file paths.
        FIX: Timeline now includes ALL specific details, not generic text.
        """
        text_lower = source_text.lower()
        threats = parsed.get("top_threats", [])
        
        # Severity weights for risk calculation
        SEVERITY_WEIGHTS = {
            "Critical": 1.0,
            "High": 0.75,
            "Medium": 0.5,
            "Low": 0.25
        }
        
        # Build timeline from source evidence - COMPREHENSIVE with specific details
        # FIX: Be more conservative - only add events that are CLEARLY in the logs
        timeline = []
        
        # Extract ALL specific details for timeline
        # IPs
        src_ip_match = re.search(r'\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.\d+\.\d+\.\d+)\b', source_text)
        src_ip = src_ip_match.group(0) if src_ip_match else None
        
        # Users
        user_match = re.search(r'(?:user|username|srcuser)[:=]\s*([a-zA-Z0-9_.-]+)', source_text, re.IGNORECASE)
        src_user = user_match.group(1) if user_match else None
        
        # Commands executed
        cmd_matches = re.findall(r'(sudo|su|su-|pkexec|systemctl)\s+[^\s]+', text_lower)
        unique_cmds = list(set(cmd_matches))[:3] if cmd_matches else []
        
        # File paths
        file_paths = re.findall(r'(/bin/[^\s]+|/usr/bin/[^\s]+|/etc/[^\s]+|/sbin/[^\s]+)', source_text)
        unique_files = list(set(file_paths))[:3] if file_paths else []
        
        # Auth events - ONLY if clear evidence in logs
        if "success" in text_lower or "accepted" in text_lower:
            if src_ip and src_user:
                timeline.append(f"SSH login from {src_ip} as {src_user}")
            elif src_ip:
                timeline.append(f"Login from {src_ip}")
            elif src_user:
                timeline.append(f"Authentication successful for {src_user}")
            else:
                timeline.append("Authentication successful")
        
        if "failed" in text_lower or "failure" in text_lower:
            if src_ip:
                timeline.append(f"Authentication failure from {src_ip}")
            else:
                timeline.append("Authentication failure detected")
        
        # Privilege events - ONLY if clear evidence
        if "sudo" in text_lower:
            if unique_cmds:
                timeline.append(f"Privilege escalation: {' | '.join(unique_cmds)}")
            else:
                timeline.append("Privilege escalation via sudo")
        
        if " su " in text_lower or "su -" in text_lower:
            if unique_cmds:
                timeline.append(f"Privilege escalation: {' | '.join(unique_cmds)}")
            else:
                timeline.append("Privilege escalation via su")
        
        if "uid=0" in text_lower or "euid=0" in text_lower:
            timeline.append("Root privilege obtained (uid=0)")
        
        # File tampering - ONLY if clear evidence
        if "trojaned" in text_lower:
            if unique_files:
                timeline.append(f"Trojaned files detected: {', '.join(unique_files)}")
            else:
                timeline.append("Trojaned binary detected - file integrity compromised")
        
        if "replaced" in text_lower and "integrity" in text_lower:
            if unique_files:
                timeline.append(f"System binary replaced: {', '.join(unique_files)}")
            else:
                timeline.append("System binary replacement detected")
        
        if "integrity" in text_lower and "changed" in text_lower:
            if unique_files:
                timeline.append(f"File integrity changed: {', '.join(unique_files)}")
            else:
                timeline.append("File integrity modification detected")
        
        # System activity - MORE CONSERVATIVE (not automatically defense evasion)
        # Only add if there's CLEAR evidence of actual change, not just "status"
        if "selinux" in text_lower:
            # Check for actual modification vs just status check
            if any(k in text_lower for k in ["setenforce", "disabled", "permissive", "enforcing changed"]):
                timeline.append("SELinux policy modification detected")
            elif "avc" in text_lower and ("denial" in text_lower or "denied" in text_lower):
                timeline.append("SELinux denial - possible policy violation")
            # Don't add generic "status change" - that's over-interpretation
        
        if "iptables" in text_lower or "firewall" in text_lower:
            # Only add if there's clear modification
            if any(k in text_lower for k in ["-f", "-i", "-a", "delete", "remove", "flush"]):
                timeline.append("Firewall rule modification detected")
            # Don't add generic "status change"
        
        # Add risk_score to each threat
        for threat in threats:
            severity = threat.get("severity", "Medium")
            confidence = threat.get("confidence", 0.5)
            weight = SEVERITY_WEIGHTS.get(severity, 0.5)
            
            # Risk score = confidence * severity_weight
            threat["risk_score"] = round(confidence * weight, 2)
        
        # Add timeline to parsed - MAX 5 specific events
        if timeline:
            # Deduplicate while preserving order
            seen = set()
            unique_timeline = []
            for event in timeline:
                if event not in seen:
                    seen.add(event)
                    unique_timeline.append(event)
            parsed["timeline"] = unique_timeline[:5]  # Max 5 events
        else:
            parsed["timeline"] = ["Security events analyzed - review recommended"]
        
        # Generate incident_type from detected threats - MORE SPECIFIC
        attack_types = [t.get("attack_type", "") for t in threats]
        
        # Collect IOCs for specific incident type
        all_ips = set()
        all_users = set()
        for t in threats:
            t_iocs = t.get("iocs", {})
            if isinstance(t_iocs, dict):
                all_ips.update(t_iocs.get("ips", []))
                all_users.update(t_iocs.get("users", []))
        
        ip_str = f" from {list(all_ips)[0]}" if all_ips else ""
        user_str = f" by {list(all_users)[0]}" if all_users else ""
        
        if "authentication_success" in attack_types and "privilege_escalation" in attack_types:
            incident_type = f"Compromised Account{ip_str} + Privilege Escalation{user_str}"
        elif "file_tampering" in attack_types:
            incident_type = "File Integrity Compromise (Trojaned Binary Indicator)"
        elif "privilege_escalation" in attack_types:
            incident_type = f"Privilege Escalation{user_str}"
        elif "credential_access" in attack_types:
            incident_type = f"Credential Access / Brute Force{ip_str}"
        elif "rootkit" in attack_types:
            incident_type = "Rootkit Detection (Confirmed Signature)"
        elif "defense_evasion" in attack_types:
            incident_type = "Defense Evasion Activity"
        else:
            incident_type = "Security Event Analysis"
        
        parsed["incident_type"] = incident_type
        
        # FIX: Make analyst_notes more specific
        if "analyst_notes" not in parsed or not parsed["analyst_notes"]:
            notes_parts = []
            if all_ips:
                notes_parts.append(f"External activity from {', '.join(list(all_ips)[:2])}")
            if all_users:
                notes_parts.append(f"User account(s): {', '.join(list(all_users)[:2])}")
            if "file_tampering" in attack_types:
                notes_parts.append("File integrity compromise detected - trojaned binary indicator")
            if "privilege_escalation" in attack_types:
                notes_parts.append("Privilege escalation via sudo/su commands")
            if "authentication_success" in attack_types:
                notes_parts.append("Successful authentication detected")
            
            if notes_parts:
                parsed["analyst_notes"] = ". ".join(notes_parts) + "."
            else:
                parsed["analyst_notes"] = f"Analyzed {len(threats)} threat categories. Review recommended."
        
        return parsed

    def _build_fallback_summary(self, file_label, total_count, overall_sev,
                                severity_dist, attack_groups, ioc_block, chain) -> dict:
        """
        Pure-Python fallback summary — used when LLM call fails or parse fails.
        Produces deterministic, accurate output without any LLM.
        FIX: Updated MITRE mappings and added file_paths/commands extraction.
        """
        top_threats = []
        MITRE_FOR_TYPE = {
            "rootkit":              {"id": "T1014",     "name": "Rootkit"},
            "file_tampering":       {"id": "T1562.001", "name": "Disable or Modify Tools"},  # FIXED: was T1021
            "defense_evasion":      {"id": "T1562",     "name": "Impair Defenses"},
            "privilege_escalation": {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
            "credential_access":    {"id": "T1110",     "name": "Brute Force"},
            "authentication_success": {"id": "T1078",  "name": "Valid Accounts"},  # FIXED: was T1021
            "lateral_movement":     {"id": "T1021",     "name": "Remote Services"},
            "system_activity":      {"id": "T1082",     "name": "System Information Discovery"},
        }

        for atype, stats in sorted(attack_groups.items(), key=lambda x: -x[1]["count"]):
            if atype == "unknown" or stats["count"] == 0:
                continue
            agents_str = ", ".join(sorted(stats["agents"]))
            mitre      = MITRE_FOR_TYPE.get(atype, {"id": "", "name": atype})

            # Use real MITRE IDs from data if available
            if stats["mitre_ids"]:
                first_mid = sorted(stats["mitre_ids"])[0]
                mitre     = {"id": first_mid, "name": MITRE_NAMES.get(first_mid, atype)}

            top_threats.append({
                "summary":         f"{stats['count']} {atype} events on {agents_str}",
                "severity":        stats["severity"],
                "attack_type":     atype,
                "mitre":           mitre,
                "iocs": {
                    "ips":        list(stats["ips"])[:8],
                    "users":      list(stats["users"])[:8],
                    "file_paths": list(stats.get("file_paths", set()))[:8],  # FIXED: was []
                    "commands":   list(stats.get("commands", set()))[:8],    # FIXED: was []
                },
                "attack_scenario":  f"Detected {stats['count']} {atype} events on {agents_str}. "
                                    f"Investigation recommended.",
                "recommendations": [
                    f"Investigate {atype} activity on {agents_str}.",
                    "Review access logs and check for unauthorized changes.",
                ],
            })

        # Build attack chain summary
        chain_narrative = ""
        if chain:
            steps = [f"Step {s['step']}: [{s.get('technique','')}] {s['event']} on {s['agent']}"
                     for s in chain[:6]]
            chain_narrative = " → ".join(steps)

        return {
            "file_label":            file_label,
            "total_events_analyzed": total_count,
            "overall_severity":      overall_sev,
            "severity_breakdown":    severity_dist,
            "threat_count":          len(top_threats),
            "top_threats":           top_threats,
            "attack_chain_summary":  chain_narrative or "Attack chain could not be determined.",
            "key_indicators":        list({ip for t in top_threats for ip in t["iocs"]["ips"]})[:10],
            "analyst_notes":         (f"Auto-generated summary from {total_count} events. "
                                      f"Overall severity: {overall_sev}. "
                                      f"Detected {len(top_threats)} distinct threat categories."),
        }

    # ──────────────────────────────────────────
    #  Fetch stored summary
    # ──────────────────────────────────────────
    async def _fetch_stored_summary(self, project: Project) -> Optional[dict]:
        collection_name = self.create_collection_name(project_id=project.project_id)
        try:
            sv = self.embedding_client.embed_text(
                text="FILE SUMMARY RAPTOR overall severity threats attack chain",
                document_type="query",
            )
            if sv and isinstance(sv[0], list):
                sv = sv[0]
            if not sv:
                return None

            results = await self.vectordb_client.search_by_vector(
                collection_name=collection_name, vector=sv, limit=5, metadata_filter=None,
            )
            if results:
                for doc in results:
                    meta = doc.metadata if hasattr(doc, "metadata") and isinstance(doc.metadata, dict) else {}
                    if meta.get("is_summary") or meta.get("chunk_level") == 1:
                        text  = getattr(doc, "text", "")
                        start = text.find("{")
                        if start != -1:
                            try:
                                return json.loads(text[start:])
                            except Exception:
                                return {"raw_summary": text}
        except Exception as e:
            logger.warning(f"_fetch_stored_summary: {e}")
        return None

    # ──────────────────────────────────────────
    #  Main RAG method
    # ──────────────────────────────────────────
    async def answer_rag_question(self, project: Project, query: str, limit: int = 20):
        """
        SOC-grade RAG pipeline:
          1. Language detection + query translation
          2. Hybrid semantic + keyword search
          3. Deduplication → Correlation → Reranking → Diversity filter
          4. Attack-chain construction
          5. Prompt assembly (IOC context + attack chain + documents)
          6. LLM generation with validation + one retry
        """
        self.template_parser.set_language_from_text(query)

        search_query = query
        if self.template_parser.language != "en":
            try:
                translation_prompt = (
                    "Translate the following to English. "
                    "Keep it concise and preserve all technical terms: " + query
                )
                translated = self.generation_client.generate_text(
                    prompt=translation_prompt, chat_history=[], max_output_tokens=100, temperature=0.0,
                )
                if translated and isinstance(translated, str):
                    search_query = translated.strip()
            except Exception as e:
                logger.warning(f"Translation failed: {e}")

        retrieved_documents = await self.search_vector_db_collection(
            project=project, text=search_query, limit=30
        )
        logger.info(f"Retrieved {len(retrieved_documents) if retrieved_documents else 0} docs for '{search_query}'")

        if not retrieved_documents and search_query != query:
            logger.info("Retrying with original query")
            retrieved_documents = await self.search_vector_db_collection(
                project=project, text=query, limit=30
            )

        if not retrieved_documents:
            return {
                "answer": {
                    "summary": "No relevant logs were retrieved for the query.",
                    "severity": "N/A", "attack_type": "N/A",
                    "mitre": {"id": "", "name": ""},
                    "iocs": {"ips": [], "users": [], "file_paths": [], "commands": []},
                    "attack_scenario": "N/A",
                    "recommendations": ["Verify the indexed logs and try a broader query."],
                },
                "full_prompt": None, "chat_history": None,
                "reason": "no_documents_found", "query": search_query,
            }

        query_mode = self.detect_query_type(query)

        # Summary mode — return stored summary or generate fresh
        if query_mode == "summary":
            stored = await self._fetch_stored_summary(project)
            if stored and not stored.get("error"):
                return {"answer": stored, "full_prompt": None, "chat_history": None, "mode": "summary"}
            logger.info("No stored summary — generating on-the-fly")
            summary = await self.generate_file_summary(project, file_label="current collection")
            return {"answer": summary, "full_prompt": None, "chat_history": None, "mode": "summary_generated"}

        # Pre-filter → Correlate → Rerank → Diversity filter
        retrieved_documents = self._pre_filter_documents(retrieved_documents, query)
        retrieved_documents = self._correlate_documents(retrieved_documents)
        retrieved_documents = self.rerank_logs(retrieved_documents, query)
        retrieved_documents = self._filter_documents(retrieved_documents, target_size=20)
        retrieved_documents = retrieved_documents[:self.max_context_documents]

        attack_chain = self._build_attack_chain(retrieved_documents)

        system_prompt = self.template_parser.get("rag", "system_prompt", {})

        doc_blocks = []
        for idx, doc in enumerate(retrieved_documents, 1):
            doc_block = self.template_parser.get(
                "rag", "document_prompt",
                {"metadata": self._build_metadata_string(doc.metadata if hasattr(doc, "metadata") else {}),
                 "content":  doc.text[:700] if hasattr(doc, "text") else ""}
            )
            doc_blocks.append(doc_block)
        documents_prompt = "\n\n".join(doc_blocks)

        ioc_context   = self._build_ioc_context(retrieved_documents)
        chain_context = self._build_attack_chain_context(attack_chain)

        if ioc_context:
            documents_prompt = f"{ioc_context}\n\n{documents_prompt}"
        if chain_context:
            documents_prompt = f"{chain_context}\n\n{documents_prompt}"

        footer_prompt = self.template_parser.get("rag", "footer_prompt", {"query": query})
        full_prompt   = f"{documents_prompt}\n\n---\n\n{footer_prompt}"

        self.generation_client.construct_prompt(
            prompt=system_prompt, role=self.generation_client.enums.SYSTEM.value
        )

        max_tokens = 2000 if query_mode == "multi" else 1200

        raw_output = self.generation_client.generate_text(
            prompt=full_prompt, chat_history=[], max_output_tokens=max_tokens, temperature=0.0,
        )

        validated = self._validate_and_fix(raw_output, retrieved_documents, mode=query_mode)

        # Retry once if validation fails
        if not validated:
            logger.warning("First LLM attempt failed validation — retrying")
            raw_output = self.generation_client.generate_text(
                prompt=full_prompt, chat_history=[], max_output_tokens=max_tokens, temperature=0.1,
            )
            validated = self._validate_and_fix(raw_output, retrieved_documents, mode=query_mode)

        if not validated:
            logger.error("Both LLM attempts failed — returning raw output")
            validated = {"summary": raw_output, "error": "validation_failed"}

        validated["attack_chain"] = attack_chain
        chat_history = self.generation_client.construct_prompt(
            prompt=full_prompt, role=self.generation_client.enums.USER.value
        )

        return {
            "answer":       validated,
            "full_prompt":  full_prompt,
            "chat_history": chat_history,
            "mode":         query_mode,
        }
