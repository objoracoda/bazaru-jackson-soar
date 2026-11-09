
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
            """),
            conn.execute("""
    CREATE TABLE IF NOT EXISTS incident_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id INTEGER NOT NULL,
        action TEXT NOT NULL,
        old_value TEXT,
        new_value TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (incident_id) REFERENCES alerts(id)
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
    if status not in ("new", "in_progress", "closed"):
        raise ValueError("Invalid status")

    init_db()

    with closing(sqlite3.connect(DB_PATH)) as conn:
        with conn:
            row = conn.execute(
                "SELECT status FROM alerts WHERE id = ?",
                (incident_id,),
            ).fetchone()

            if row is None:
                return False

            old_status = row[0]

            if old_status == status:
                return True

            conn.execute(
                "UPDATE alerts SET status = ? WHERE id = ?",
                (status, incident_id),
            )

            conn.execute("""
                INSERT INTO incident_history (
                    incident_id, action, old_value, new_value
                )
                VALUES (?, 'status_changed', ?, ?)
            """, (incident_id, old_status, status))

    return True


def get_incident(incident_id):
    init_db()

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row

        row = conn.execute(
            "SELECT * FROM alerts WHERE id = ?",
            (incident_id,),
        ).fetchone()

        return dict(row) if row else None


def get_incident_history(incident_id):
    init_db()

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute("""
            SELECT *
            FROM incident_history
            WHERE incident_id = ?
            ORDER BY id DESC
        """, (incident_id,)).fetchall()

        return [dict(row) for row in rows]


def add_incident_comment(incident_id, comment):
    comment = comment.strip()

    if not comment or len(comment) > 2000:
        raise ValueError("Comment must contain 1-2000 characters")

    init_db()

    with closing(sqlite3.connect(DB_PATH)) as conn:
        with conn:
            exists = conn.execute(
                "SELECT 1 FROM alerts WHERE id = ?",
                (incident_id,),
            ).fetchone()

            if not exists:
                return False

            conn.execute("""
                INSERT INTO incident_history (
                    incident_id, action, new_value
                )
                VALUES (?, 'comment', ?)
            """, (incident_id, comment))

    return True

