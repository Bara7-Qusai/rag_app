# aggregator.py
"""
Event aggregation and statistical analysis module.
Groups events, computes statistics, and prepares data for summarization.
"""

from collections import defaultdict, Counter
from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime, timedelta
from .parser import ParsedEvent
from .detector import ThreatDetector

class EventAggregator:
    """Aggregates security events and computes statistical summaries."""

    def __init__(self):
        self.detector = ThreatDetector()

    def aggregate_events(self, events: List[ParsedEvent]) -> Dict:
        """
        Aggregate events into structured groups with statistics.
        Returns comprehensive aggregation results.
        """
        if not events:
            return self._empty_aggregation()

        # Initialize aggregation structures
        attack_groups = defaultdict(lambda: {
            'count': 0,
            'events': [],
            'agents': set(),
            'ips': set(),
            'users': set(),
            'mitre_techniques': set(),
            'severity_levels': [],
            'timestamps': [],
            'rule_ids': set(),
            'max_severity': 0,
            'min_severity': 15,
            'time_span': None
        })

        total_stats = {
            'total_events': len(events),
            'unique_agents': set(),
            'unique_ips': set(),
            'unique_users': set(),
            'severity_distribution': defaultdict(int),
            'time_range': {'start': None, 'end': None},
            'rule_distribution': defaultdict(int),
            'mitre_coverage': set()
        }

        # Process each event
        for event in events:
            classification = self.detector.classify_event(event)

            # Update total statistics
            total_stats['unique_agents'].add(event.agent or 'unknown')
            if event.agent_ip:
                total_stats['unique_ips'].add(event.agent_ip)
            extracted_user = event.extracted_fields.get('user')
            if extracted_user:
                total_stats['unique_users'].add(extracted_user)

            total_stats['severity_distribution'][classification['severity']] += 1
            total_stats['rule_distribution'][event.rule_id or 'unknown'] += 1
            total_stats['mitre_coverage'].update(event.mitre_ids)

            # Update time range
            if event.timestamp:
                event_time = self._parse_timestamp(event.timestamp)
                if event_time:
                    if not total_stats['time_range']['start'] or event_time < total_stats['time_range']['start']:
                        total_stats['time_range']['start'] = event_time
                    if not total_stats['time_range']['end'] or event_time > total_stats['time_range']['end']:
                        total_stats['time_range']['end'] = event_time

            # Group by primary attack type
            primary_type = classification['primary_attack_type']
            group = attack_groups[primary_type]

            group['count'] += 1
            group['events'].append({
                'event': event,
                'classification': classification,
                'timestamp': event.timestamp
            })

            if event.agent:
                group['agents'].add(event.agent)
            if event.agent_ip:
                group['ips'].add(event.agent_ip)
            if extracted_user:
                group['users'].add(extracted_user)

            group['mitre_techniques'].update(classification['mitre_techniques'])
            group['severity_levels'].append(classification['severity'])
            group['rule_ids'].add(event.rule_id or 'unknown')

            if event.timestamp:
                group['timestamps'].append(event.timestamp)

            # Update severity bounds
            sev = classification['severity']
            group['max_severity'] = max(group['max_severity'], sev)
            group['min_severity'] = min(group['min_severity'], sev)

        # Post-process groups
        processed_groups = {}
        for attack_type, group_data in attack_groups.items():
            processed_groups[attack_type] = self._process_attack_group(attack_type, group_data)

        # Finalize total statistics
        total_stats['unique_agents'] = len(total_stats['unique_agents'])
        total_stats['unique_ips'] = len(total_stats['unique_ips'])
        total_stats['unique_users'] = len(total_stats['unique_users'])
        total_stats['mitre_coverage'] = list(total_stats['mitre_coverage'])

        # Calculate overall severity
        overall_severity = self._calculate_overall_severity(total_stats['severity_distribution'])

        return {
            'total_events': total_stats['total_events'],
            'overall_severity': overall_severity,
            'severity_distribution': dict(total_stats['severity_distribution']),
            'time_range': {
                'start': total_stats['time_range']['start'].isoformat() if total_stats['time_range']['start'] else None,
                'end': total_stats['time_range']['end'].isoformat() if total_stats['time_range']['end'] else None,
                'duration_hours': self._calculate_duration_hours(total_stats['time_range'])
            },
            'unique_counts': {
                'agents': total_stats['unique_agents'],
                'ips': total_stats['unique_ips'],
                'users': total_stats['unique_users']
            },
            'attack_groups': processed_groups,
            'top_rules': dict(sorted(total_stats['rule_distribution'].items(),
                                   key=lambda x: x[1], reverse=True)[:10]),
            'mitre_coverage': total_stats['mitre_coverage'],
            'anomalies': self.detector.detect_anomalies(events),
            'attack_chains': self.detector.get_attack_chain_indicators(events)
        }

    def _process_attack_group(self, attack_type: str, group_data: Dict) -> Dict:
        """Process and enrich an attack group with additional statistics."""
        # Calculate time span
        timestamps = []
        for ts in group_data['timestamps']:
            parsed = self._parse_timestamp(ts)
            if parsed:
                timestamps.append(parsed)

        time_span = None
        if timestamps:
            timestamps.sort()
            if len(timestamps) > 1:
                time_span = (timestamps[-1] - timestamps[0]).total_seconds() / 3600  # hours

        # Calculate severity statistics
        severity_levels = group_data['severity_levels']
        avg_severity = sum(severity_levels) / len(severity_levels) if severity_levels else 0

        # Determine severity category
        max_sev = group_data['max_severity']
        severity_category = (
            "Critical" if max_sev >= 12 else
            "High" if max_sev >= 7 else
            "Medium" if max_sev >= 4 else "Low"
        )

        # Extract IOCs
        iocs = self._extract_group_iocs(group_data)

        return {
            'count': group_data['count'],
            'severity': {
                'max': group_data['max_severity'],
                'min': group_data['min_severity'],
                'average': round(avg_severity, 2),
                'category': severity_category
            },
            'affected_entities': {
                'agents': sorted(list(group_data['agents'])),
                'ips': sorted(list(group_data['ips'])),
                'users': sorted(list(group_data['users']))
            },
            'mitre_techniques': sorted(list(group_data['mitre_techniques'])),
            'rule_ids': sorted(list(group_data['rule_ids'])),
            'time_span_hours': time_span,
            'iocs': iocs,
            'frequency_per_hour': self._calculate_frequency(group_data, time_span),
            'sample_events': group_data['events'][:5]  # Keep sample for context
        }

    def _extract_group_iocs(self, group_data: Dict) -> Dict:
        """Extract indicators of compromise from group events."""
        iocs = {
            'ips': set(),
            'users': set(),
            'file_paths': set(),
            'commands': set(),
            'hashes': set(),
            'domains': set()
        }

        for event_data in group_data['events']:
            event = event_data['event']
            fields = event.extracted_fields

            # Extract from structured fields
            if fields.get('src_ip'):
                iocs['ips'].add(fields['src_ip'])
            if fields.get('dst_ip'):
                iocs['ips'].add(fields['dst_ip'])
            if fields.get('user'):
                iocs['users'].add(fields['user'])
            if fields.get('file_path'):
                iocs['file_paths'].add(fields['file_path'])
            if fields.get('command'):
                iocs['commands'].add(fields['command'])

            # Extract from raw log using regex
            raw_log = event.raw_log.lower()

            # IP addresses
            import re
            ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
            iocs['ips'].update(ip_pattern.findall(raw_log))

            # Users
            user_pattern = re.compile(r'user[=:]\s*([a-zA-Z0-9_.-]+)', re.IGNORECASE)
            iocs['users'].update(user_pattern.findall(raw_log))

            # File paths
            path_pattern = re.compile(r'(/[^\s"\'<>]{4,}|[A-Za-z]:\\[^\s"\'<>]{4,})')
            iocs['file_paths'].update(path_pattern.findall(raw_log))

        # Clean and limit IOCs
        return {
            'ips': sorted(list(iocs['ips'] - {'0.0.0.0', '127.0.0.1'}))[:10],
            'users': sorted(list(iocs['users'] - {'_', 'N/A', ''}))[:10],
            'file_paths': sorted(list(iocs['file_paths']))[:10],
            'commands': sorted(list(iocs['commands']))[:10],
            'hashes': sorted(list(iocs['hashes']))[:5],
            'domains': sorted(list(iocs['domains']))[:5]
        }

    def _calculate_frequency(self, group_data: Dict, time_span: Optional[float]) -> Optional[float]:
        """Calculate event frequency per hour."""
        if not time_span or time_span <= 0:
            return None
        return group_data['count'] / time_span

    def _calculate_overall_severity(self, severity_dist: Dict[int, int]) -> str:
        """Calculate overall severity from distribution."""
        if not severity_dist:
            return "Low"

        total_events = sum(severity_dist.values())
        weighted_score = sum(level * count for level, count in severity_dist.items()) / total_events

        if weighted_score >= 12:
            return "Critical"
        elif weighted_score >= 7:
            return "High"
        elif weighted_score >= 4:
            return "Medium"
        else:
            return "Low"

    def _calculate_duration_hours(self, time_range: Dict) -> Optional[float]:
        """Calculate total duration in hours."""
        if not time_range['start'] or not time_range['end']:
            return None
        return (time_range['end'] - time_range['start']).total_seconds() / 3600

    def _parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse timestamp string to datetime object."""
        if not timestamp_str:
            return None

        try:
            # Try ISO format first
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except:
            pass

        # Try common formats
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%b %d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S"
        ]

        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except:
                continue

        return None

    def _empty_aggregation(self) -> Dict:
        """Return empty aggregation structure."""
        return {
            'total_events': 0,
            'overall_severity': 'Low',
            'severity_distribution': {},
            'time_range': {'start': None, 'end': None, 'duration_hours': None},
            'unique_counts': {'agents': 0, 'ips': 0, 'users': 0},
            'attack_groups': {},
            'top_rules': {},
            'mitre_coverage': [],
            'anomalies': [],
            'attack_chains': []
        }

    def get_grouped_threats_summary(self, aggregation: Dict) -> str:
        """
        Generate a human-readable summary of grouped threats for LLM prompts.
        This ensures exact counts are provided without hallucination.
        """
        if not aggregation.get('attack_groups'):
            return "No threat groups identified."

        lines = [f"GROUPED THREATS (computed from {aggregation['total_events']} events):"]

        for attack_type, group in sorted(aggregation['attack_groups'].items(),
                                       key=lambda x: x[1]['count'], reverse=True):
            agents = group['affected_entities']['agents']
            ips = group['affected_entities']['ips']
            users = group['affected_entities']['users']
            mitre_list = ", ".join(group['mitre_techniques']) or "inferred"

            lines.append(
                f"  [{attack_type}] count={group['count']} | severity={group['severity']['category']}(L{group['severity']['max']}) "
                f"| agents={', '.join(agents) or 'N/A'} | ips={', '.join(ips) or 'N/A'} | users={', '.join(users) or 'N/A'} "
                f"| mitre={mitre_list}"
            )

        return "\n".join(lines)