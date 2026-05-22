
import json
import os
from datetime import datetime, timezone

TARGETS = set([h.strip().lower() for h in os.getenv('AI_TARGETS', '').split(',') if h.strip()])
OUTPUT_FILE = os.getenv('AI_PROXY_OUTPUT', '')


def _match_host(host: str) -> bool:
    host = (host or '').lower()
    if not host:
        return False
    return any(host == t or host.endswith('.' + t) for t in TARGETS)


def _write(payload):
    if not OUTPUT_FILE:
        return
    with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
        f.write(json.dumps(payload, ensure_ascii=False) + '\n')


class ADRLogger:
    def request(self, flow):
        host = flow.request.pretty_host
        if not _match_host(host):
            return
        payload = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event_type': 'network_request',
            'details': {
                'method': flow.request.method,
                'host': host,
                'path': flow.request.path,
                'scheme': flow.request.scheme,
                'port': flow.request.port,
                'client_ip': flow.client_conn.address[0] if flow.client_conn and flow.client_conn.address else None,
            },
            'risk_level': 'low',
            'agent_detected': None,
            'source': 'network_monitor_proxy'
        }
        _write(payload)


addons = [ADRLogger()]
