"""Draft narrow Wazuh XML exceptions; NEVER modify Wazuh configuration."""
import re
import xml.etree.ElementTree as ET
from app.services.ai import read_path

class TuningError(Exception):
    pass


def literal_pcre(value):
    """Match only a literal decoded field value, not a wildcard path pattern."""
    if not isinstance(value, str) or not (5 <= len(value) <= 500):
        raise TuningError('Не хватает проверенного конкретного значения поля.')
    if any(ord(c) < 32 for c in value):
        raise TuningError('Недопустимое управляющее значение поля.')
    return '^' + re.escape(value) + '$'


def propose_exception(incident, raw_event, rule_id):
    """Safe, exact, review-only XML. Must logtest with benign and malicious samples."""
    if not isinstance(rule_id, int) or not 100000 <= rule_id <= 119999:
        raise TuningError('Для нового правила нужен свободный ID из диапазона 100000–119999.')
    parent = str(incident.get('rule_id') or '')
    if not parent.isdigit():
        raise TuningError('Исходный Rule ID должен быть числом.')
    # The values here must exist in the *decoded Wazuh* event.
    mappings = (
        ('win.system.computer', ['data.win.system.computer', 'win.system.computer']),
        ('win.eventdata.image', ['data.win.eventdata.image', 'win.eventdata.image']),
        ('win.eventdata.targetFilename', ['data.win.eventdata.targetFilename', 'win.eventdata.targetFilename']),
    )
    extracted = []
    for field_name, paths in mappings:
        value = next((v for path in paths if isinstance((v := read_path(raw_event, path)), str) and v.strip()), None)
        if value:
            extracted.append((field_name, value))
    fields = {name for name, _ in extracted}
    if not {'win.eventdata.image', 'win.eventdata.targetFilename'}.issubset(fields):
        raise TuningError('Для безопасного примера нужны поля image и targetFilename. Не предлагаем широкое исключение.')
    group = ET.Element('group', {'name': 'local,sysmon,'})
    rule = ET.SubElement(group, 'rule', {'id': str(rule_id), 'level': '0'})
    ET.SubElement(rule, 'if_sid').text = parent
    for field_name, value in extracted:
        ET.SubElement(rule, 'field', {'name': field_name, 'type': 'pcre2'}).text = literal_pcre(value)
    ET.SubElement(rule, 'description').text = 'REVIEWED exact-match suppression candidate - verify with wazuh-logtest'
    ET.indent(group, space='  ')
    xml = ET.tostring(group, encoding='unicode')
    rationale = (
        'Черновик для проверки, НЕ установлен. Исходный вердикт аналитика — False Positive. '
        'Условия соответствуют точным значениям одного события и не покрывают другие временные каталоги. '
        'Повторяемость только по Rule ID и агенту не доказывает идентичность событий. '
        'Проверь подписи и происхождение файлов, наличие конфликтов ID и условия через wazuh-logtest. '
        'Создай как минимум один подтверждённо штатный и один атакующий контрольный пример; '
        'убедись, что последний НЕ подавляется. Level 0 может скрыть важную телеметрию.'
    )
    return {'xml': xml, 'rationale': rationale}

