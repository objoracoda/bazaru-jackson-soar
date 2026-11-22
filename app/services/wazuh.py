
import os
import re
from urllib.parse import quote

import requests
from requests.auth import HTTPBasicAuth


class WazuhClient:
    def __init__(self):
        self.url = os.environ["WAZUH_INDEXER_URL"].rstrip("/")
        self.username = os.environ["WAZUH_INDEXER_USER"]
        self.password = os.environ["WAZUH_INDEXER_PASSWORD"]
        self.ca_cert = os.environ["WAZUH_CA_CERT"]

    def _request_search(self, query):
        endpoint = f"{self.url}/wazuh-alerts-*/_search"

        response = requests.post(
            endpoint,
            params={"preference": "bazaru-sync"},
            json=query,
            auth=HTTPBasicAuth(
                self.username,
                self.password,
            ),
            verify=self.ca_cert,
            timeout=30,
        )

        response.raise_for_status()
        data = response.json()

        if data.get("timed_out"):
            raise RuntimeError("Wazuh Indexer search timed out")

        if data.get("_shards", {}).get("failed", 0):
            raise RuntimeError("Wazuh Indexer shard failure")

        return data

    @staticmethod
    def _normalize_hit(hit):
        event = hit["_source"]
        rule = event.get("rule", {})
        agent = event.get("agent", {})

        return {
            "id": hit["_id"],
            "index": hit["_index"],
            "agent": agent.get("name"),
            "rule_id": rule.get("id"),
            "level": rule.get("level"),
            "description": rule.get("description"),
            "timestamp": event.get("@timestamp"),
        }

    @staticmethod
    def _get_total(data):
        total = data["hits"]["total"]

        if isinstance(total, dict):
            return total["value"]

        return total

    def get_alerts(self, min_level=7, limit=20):
        """
        Получить последние алерты Wazuh.
        Используется существующим API и веб-панелью.
        """
        query = {
            "size": limit,
            "track_total_hits": True,
            "query": {
                "range": {
                    "rule.level": {
                        "gte": min_level,
                    }
                }
            },
            "sort": [
                {
                    "@timestamp": {
                        "order": "desc",
                    }
                }
            ],
        }

        data = self._request_search(query)

        alerts = [
            self._normalize_hit(hit)
            for hit in data["hits"]["hits"]
        ]

        return {
            "total": self._get_total(data),
            "alerts": alerts,
        }

    def get_alert_document(self, index, document_id):
        """
        Получить полное исходное событие Wazuh.
        Используется карточкой расследования.
        """
        if not re.fullmatch(
            r"wazuh-alerts-[A-Za-z0-9._-]+",
            index,
        ):
            raise ValueError("Invalid Wazuh index")

        safe_id = quote(document_id, safe="")
        endpoint = f"{self.url}/{index}/_doc/{safe_id}"

        response = requests.get(
            endpoint,
            auth=HTTPBasicAuth(
                self.username,
                self.password,
            ),
            verify=self.ca_cert,
            timeout=15,
        )

        if response.status_code == 404:
            return None

        response.raise_for_status()

        return response.json().get("_source")

    def get_alerts_page(
        self,
        start_time,
        end_time,
        offset=0,
        page_size=500,
    ):
        """
        Получить страницу алертов уровня 7-16
        за указанный временной интервал.
        """
        if not 1 <= page_size <= 1000:
            raise ValueError("Invalid page size")

        if offset < 0:
            raise ValueError("Invalid offset")

        query = {
            "from": offset,
            "size": page_size,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "rule.level": {
                                    "gte": 7,
                                    "lte": 16,
                                }
                            }
                        },
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": start_time,
                                    "lte": end_time,
                                }
                            }
                        },
                    ]
                }
            },
            "sort": [
                {
                    "@timestamp": {
                        "order": "asc",
                    }
                }
            ],
        }

        data = self._request_search(query)

        alerts = [
            self._normalize_hit(hit)
            for hit in data["hits"]["hits"]
        ]

        return {
            "total": self._get_total(data),
            "alerts": alerts,
        }

