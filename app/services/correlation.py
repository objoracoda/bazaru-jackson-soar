"""Correlate Wazuh *alerts*, never claim this is complete Sysmon telemetry."""
from datetime import datetime, timedelta, timezone
import requests
from app.services.ai import build_event_context, extract_technical_details, redact_sensitive
from app.services.wazuh import WazuhClient

WINDOW_MINUTES = 15
SEARCH_LIMIT = 300
RELATED_LIMIT = 20

class CorrelationError(Exception):
    pass


def parse_timestamp(value):
    try:
        item = datetime.fromisoformat(str(value).replace('Z', '+00:00'))
        return (item if item.tzinfo else item.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except (ValueError, TypeError) as exc:
        raise CorrelationError('Не удалось определить время события.') from exc


def fmt_time(value):
    return value.isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def extract_agent_filter(incident, raw_event):
    agent = raw_event.get('agent') or {}
    if isinstance(agent, dict) and agent.get('id') is not None:
        return {'term': {'agent.id': str(agent['id'])}}
    if not incident.get('agent'):
        raise CorrelationError('В алерте отсутствует агент.')
    return {'bool': {'should': [
        {'term': {'agent.name.keyword': incident['agent']}},
        {'match_phrase': {'agent.name': incident['agent']}},
    ], 'minimum_should_match': 1}}


def compact(hit, original_details):
    source = hit.get('_source') or {}
    details = extract_technical_details(source)
    base_guid = str(original_details.get('process_guid') or '').casefold()
    this_guid = str(details.get('process_guid') or '').casefold()
    base_path = str(original_details.get('target_filename') or original_details.get('file_path') or '').casefold()
    this_path = str(details.get('target_filename') or details.get('file_path') or '').casefold()
    if base_guid and this_guid and base_guid == this_guid:
        relation, priority = 'same_process_guid', 0
    elif base_path and this_path and base_path == this_path:
        relation, priority = 'same_file_path', 1
    else:
        relation, priority = 'same_agent_time_window', 2
    allowed = (
        'windows_event_id', 'process_guid', 'process_image', 'command_line',
        'parent_image', 'parent_command_line', 'target_filename', 'process_id',
        'sha256', 'destination_ip', 'destination_port', 'dns_query',
    )
    rule = source.get('rule') or {}
    return {
        'timestamp': str(source.get('@timestamp') or '')[:80],
        'rule_id': str(rule.get('id') or '')[:40],
        'rule_level': rule.get('level'),
        'description': redact_sensitive(rule.get('description') or '')[:240],
        'relation': relation,
        'priority': priority,
        'technical_details': {key: details[key][:240] for key in allowed if key in details},
    }


def find_related_alerts(incident, raw_event):
    target_time = parse_timestamp(incident.get('event_time'))
    window_start = target_time - timedelta(minutes=WINDOW_MINUTES)
    window_end = target_time + timedelta(minutes=WINDOW_MINUTES)
    base = extract_technical_details(raw_event)
    filters = [
        {'range': {'@timestamp': {'gte': fmt_time(window_start), 'lte': fmt_time(window_end)}}},
        extract_agent_filter(incident, raw_event),
    ]
    query = {'size': SEARCH_LIMIT, 'track_total_hits': True,
             'query': {'bool': {'filter': filters}},
             'sort': [{'@timestamp': {'order': 'asc'}}]}
    data = WazuhClient()._request_search(query)
    total = data['hits']['total']
    total = total['value'] if isinstance(total, dict) else total
    events = []
    for hit in data['hits']['hits']:
        if hit.get('_id') == incident.get('wazuh_id') and hit.get('_index') == incident.get('wazuh_index'):
            continue
        item = compact(hit, base)
        try:
            delta = abs((parse_timestamp(item['timestamp']) - target_time).total_seconds())
        except CorrelationError:
            delta = float('inf')
        item['_distance'] = delta
        events.append(item)
    events.sort(key=lambda x: (x['priority'], x['_distance'], x['timestamp']))
    # Prefer concrete correlations; bound unrelated noisy Windows 4688 alerts.
    chosen, noise_count = [], 0
    seen = set()
    for event in events:
        if event['priority'] == 2:
            if noise_count >= 5:
                continue
            noise_count += 1
        fingerprint = (event['relation'], event['rule_id'], event['description'],
                       event['technical_details'].get('process_guid', ''),
                       event['technical_details'].get('process_image', ''),
                       event['technical_details'].get('command_line', ''))
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        event.pop('priority', None)
        event.pop('_distance', None)
        chosen.append(event)
        if len(chosen) == RELATED_LIMIT:
            break
    chosen.sort(key=lambda event: event['timestamp'])
    return {
        'source': 'wazuh-alerts-*', 'window_minutes': WINDOW_MINUTES,
        'window_start_utc': fmt_time(window_start), 'window_end_utc': fmt_time(window_end),
        'matched_alerts_in_window': total,
        'returned_alerts': len(chosen),
        'results_may_be_incomplete': total >= SEARCH_LIMIT,
        'limitations': 'Только алерты Wazuh; не все исходные события Sysmon. Соседство по времени не доказывает единую атаку.',
        'events': chosen,
    }


def build_correlated_context(incident, raw_event, correlation):
    result = build_event_context(incident, raw_event)
    result['correlation'] = correlation
    return result

