
import os

import requests
from requests.auth import HTTPBasicAuth

import re
from urllib.parse import quote

class WazuhClient:
    def __init__(self):
        self.url = os.environ["WAZUH_INDEXER_URL"].rstrip("/")
        self.username = os.environ["WAZUH_INDEXER_USER"]
        self.password = os.environ["WAZUH_INDEXER_PASSWORD"]
        self.ca_cert = os.environ["WAZUH_CA_CERT"]

    
    def get_alert_document(self, index: str, document_id: str):
        if not re.fullmatch(
            r"wazuh-alerts-[A-Za-z0-9._-]+", index
        ):
            raise ValueError("Invalid Wazuh index")

        safe_id = quote(document_id, safe="")
        endpoint = f"{self.url}/{index}/_doc/{safe_id}"

        response = requests.get(
            endpoint,
            auth=HTTPBasicAuth(self.username, self.password),
            verify=self.ca_cert,
            timeout=15,
        )

        if response.status_code == 404:
            return None

        response.raise_for_status()
        return response.json().get("_source")


    def get_alerts(self, min_level: int = 7, limit: int = 20):
        endpoint = f"{self.url}/wazuh-alerts-*/_search"

        query = {
            "size": limit,
            "track_total_hits": True,
            "query": {
                "range": {
                    "rule.level": {
                        "gte": min_level
                    }
                }
            },
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc"
                    }
                }
            ]
        }

        response = requests.post(
            endpoint,
            json=query,
            auth=HTTPBasicAuth(self.username, self.password),
            verify=self.ca_cert,
            timeout=15,
        )

        response.raise_for_status()
        data = response.json()

        alerts = []

        for hit in data["hits"]["hits"]:
            event = hit["_source"]
            rule = event.get("rule", {})
            agent = event.get("agent", {})

            alerts.append({
                "id": hit["_id"],
                "index": hit["_index"],
                "agent": agent.get("name"),
                "rule_id": rule.get("id"),
                "level": rule.get("level"),
                "description": rule.get("description"),
                "timestamp": event.get("@timestamp"),
            })

        total = data["hits"]["total"]

        return {
            "total": total["value"],
            "alerts": alerts
        }

