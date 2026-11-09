
import sqlite3
from contextlib import closing
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
DB_PATH = BASE_DIR / "data" / "soar.db"


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)

    with closing(sqlite3.connect(DB_PATH)) as conn:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    wazuh_index TEXT NOT NULL,
                    wazuh_id TEXT NOT NULL,
                    agent TEXT,
                    rule_id TEXT,
                    level INTEGER NOT NULL,
                    description TEXT,
                    event_time TEXT,
                    status TEXT NOT NULL DEFAULT 'new'
                        CHECK (status IN (
                            'new', 'in_progress', 'closed'
                        )),
                    imported_at TEXT NOT NULL
                        DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(wazuh_index, wazuh_id)
                )
            """)


def save_alerts(alerts):
    init_db()
    added = 0

    with closing(sqlite3.connect(DB_PATH)) as conn:
        with conn:
            for alert in alerts:
                cursor = conn.execute("""
                    INSERT OR IGNORE INTO alerts (
                        wazuh_index, wazuh_id, agent,
                        rule_id, level, description, event_time
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert["index"],
                    alert["id"],
                    alert["agent"],
                    alert["rule_id"],
                    alert["level"],
                    alert["description"],
                    alert["timestamp"],
                ))

                added += cursor.rowcount

    return added


def get_incidents(limit=50):
    init_db()

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT *
            FROM alerts
            ORDER BY event_time DESC, id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]


def update_incident_status(incident_id, status):
    init_db()

    with closing(sqlite3.connect(DB_PATH)) as conn:
        with conn:
            cursor = conn.execute("""
                UPDATE alerts
                SET status = ?
                WHERE id = ?
            """, (status, incident_id))

            return cursor.rowcount > 0

