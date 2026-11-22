import unittest
import sys
import types

# The archive intentionally does not replace the project's existing Wazuh client.
# Mock its import for offline unit tests when run outside the full repository.
if "app.services.wazuh" not in sys.modules:
    try:
        import app.services.wazuh
    except ModuleNotFoundError:
        stub = types.ModuleType("app.services.wazuh")
        stub.WazuhClient = type("WazuhClient", (), {})
        sys.modules["app.services.wazuh"] = stub
import xml.etree.ElementTree as ET

from app.services.ai import build_event_context, decision_policy, validate_analysis
from app.services.correlation import compact
from app.services.tuning import TuningError, propose_exception


class FeatureTests(unittest.TestCase):
    def setUp(self):
        self.incident = {
            'rule_id': '92213', 'level': 15, 'event_time': '2026-11-21T15:17:20Z',
            'agent': 'WIN10-LAB', 'description': 'File dropped',
        }
        self.raw = {'data': {'win': {
            'system': {'eventID': '11', 'computer': 'WIN10-LAB'},
            'eventdata': {
                'image': 'C:\\Windows\\System32\\cleanmgr.exe',
                'targetFilename': 'C:\\Users\\socadmin\\Temp\\WimProvider.dll',
                'processGuid': '{a-b}', 'processId': '5588',
            }
        }}}

    def test_context(self):
        context = build_event_context(self.incident, self.raw)
        self.assertEqual(context['technical_details']['windows_event_id'], '11')
        self.assertEqual(context['technical_details']['process_image'], 'C:\\Windows\\System32\\cleanmgr.exe')

    def test_risk_policy_prevents_false_reassurance(self):
        self.assertIn('Недостаточно', decision_policy({'risk_score': 10, 'confidence': 'low', 'evidence_completeness': 'insufficient'}))
        self.assertIn('реагирование', decision_policy({'risk_score': 91, 'confidence': 'high', 'evidence_completeness': 'sufficient'}))

    def test_unjustified_verdict_overridden(self):
        data = {
            'activity_summary': 'Обнаружено создание временного файла.',
            'description': 'Зафиксировано создание файла на тестовом хосте.',
            'investigation': 'Проверить подписи и другие события.',
            'conclusion': 'Установить легитимность пока не удалось.',
            'verdict': 'false_positive', 'risk_score': 8,
            'confidence': 'low', 'evidence_completeness': 'insufficient',
            'benign_indicators': [], 'suspicious_indicators': [], 'missing_evidence': [],
        }
        self.assertEqual(validate_analysis(data)['verdict'], 'undetermined')

    def test_tuning_xml_exact_match(self):
        draft = propose_exception(self.incident, self.raw, 100201)
        group = ET.fromstring(draft['xml'])
        self.assertEqual(group.find('rule').attrib['level'], '0')
        self.assertEqual(group.find('rule/if_sid').text, '92213')
        self.assertEqual(len(group.findall('rule/field')), 3)
        self.assertIn('WimProvider', draft['xml'])
        self.assertNotIn('.*', draft['xml'])

    def test_tuning_requires_multiple_specific_fields(self):
        with self.assertRaises(TuningError):
            propose_exception(self.incident, {'data': {'win': {'eventdata': {'image': 'C:\\Windows\\system32\\cmd.exe'}}}}, 100201)

    def test_similar_process_guid(self):
        hit = {'_source': {'@timestamp': '2026-11-21T15:17:21Z', 'rule': {'id': '67027'}, **self.raw}}
        item = compact(hit, {'process_guid': '{a-b}'})
        self.assertEqual(item['relation'], 'same_process_guid')


if __name__ == '__main__':
    unittest.main()

