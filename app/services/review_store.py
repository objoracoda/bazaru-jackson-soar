"""Persist exact reviewed AI context, reviews and tuning drafts without changing existing tables."""
import hashlib
import json
import secrets
import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from app.services.database import DB_PATH, init_db


def connect():
    init_db()
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_tables():
    with closing(connect()) as conn, conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS ai_context_snapshots (
            id TEXT PRIMARY KEY, incident_id INTEGER NOT NULL,
            owner_hash TEXT NOT NULL, context_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(incident_id) REFERENCES alerts(id))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS ai_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
            review_json TEXT NOT NULL, context_json TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(incident_id) REFERENCES alerts(id))''')
        conn.execute('''CREATE TABLE IF NOT EXISTS tuning_proposals (
            id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL,
            xml_text TEXT NOT NULL, rationale TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(incident_id) REFERENCES alerts(id))''')


def owner_hash(csrf_token):
    return hashlib.sha256(csrf_token.encode()).hexdigest()


def create_snapshot(incident_id, csrf_token, context):
    init_tables()
    serialized = json.dumps(context, ensure_ascii=False, sort_keys=True)
    if len(serialized.encode('utf-8')) > 55000:
        raise ValueError('Контекст превышает допустимый размер предпросмотра.')
    key = secrets.token_urlsafe(24)
    with closing(connect()) as conn, conn:
        conn.execute('DELETE FROM ai_context_snapshots WHERE created_at < datetime("now", "-1 day")')
        conn.execute('INSERT INTO ai_context_snapshots(id, incident_id, owner_hash, context_json) VALUES(?,?,?,?)',
                     (key, incident_id, owner_hash(csrf_token), serialized))
    return key


def consume_snapshot(snapshot_id, incident_id, csrf_token):
    init_tables()
    with closing(connect()) as conn, conn:
        row = conn.execute('''SELECT context_json FROM ai_context_snapshots
            WHERE id=? AND incident_id=? AND owner_hash=?
            AND created_at >= datetime('now', '-20 minutes')''',
            (snapshot_id, incident_id, owner_hash(csrf_token))).fetchone()
        if not row:
            return None
        conn.execute('DELETE FROM ai_context_snapshots WHERE id=?', (snapshot_id,))
        return json.loads(row[0])


def save_review(incident_id, context, review):
    init_tables()
    with closing(connect()) as conn, conn:
        cursor = conn.execute('INSERT INTO ai_reviews(incident_id, review_json, context_json) VALUES (?,?,?)',
                              (incident_id, json.dumps(review, ensure_ascii=False), json.dumps(context, ensure_ascii=False)))
        return cursor.lastrowid


def latest_review(incident_id):
    init_tables()
    with closing(connect()) as conn:
        row = conn.execute('SELECT review_json, created_at FROM ai_reviews WHERE incident_id=? ORDER BY id DESC LIMIT 1',
                           (incident_id,)).fetchone()
    return {'result': json.loads(row[0]), 'created_at': row[1]} if row else None


def similar_confirmed_fp(incident):
    """Coarse frequency gate; matching rule+agent is NOT enough to validate an exception."""
    with closing(connect()) as conn:
        return conn.execute('''SELECT COUNT(*) FROM alerts a JOIN incident_reports r ON r.incident_id=a.id
            WHERE a.rule_id=? AND a.agent=? AND r.verdict='false_positive' ''',
            (incident.get('rule_id'), incident.get('agent'))).fetchone()[0]


def save_proposal(incident_id, xml_text, rationale):
    init_tables()
    with closing(connect()) as conn, conn:
        cursor = conn.execute('INSERT INTO tuning_proposals(incident_id, xml_text, rationale) VALUES(?,?,?)',
                              (incident_id, xml_text, rationale))
        return cursor.lastrowid


def latest_proposal(incident_id):
    init_tables()
    with closing(connect()) as conn:
        row = conn.execute('SELECT xml_text, rationale, created_at FROM tuning_proposals WHERE incident_id=? ORDER BY id DESC LIMIT 1',
                           (incident_id,)).fetchone()
    return {'xml': row[0], 'rationale': row[1], 'created_at': row[2]} if row else None

