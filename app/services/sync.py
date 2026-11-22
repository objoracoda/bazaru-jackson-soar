
import logging
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from dotenv import load_dotenv

from app.services.database import (
    DB_PATH,
    init_db,
    save_alerts,
)
from app.services.wazuh import WazuhClient


BASE_DIR = Path(__file__).resolve().parents[2]
load_dotenv(BASE_DIR / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

logger = logging.getLogger("bazaru.sync")

STATE_KEY = "wazuh_sync_until"

# Количество алертов на одной странице.
PAGE_SIZE = 500

# Максимальное число событий в одном временном окне.
MAX_RESULTS = 10000

# Первый запуск: последние 24 часа.
INITIAL_LOOKBACK = timedelta(hours=24)

# Повторно проверяем предыдущие 5 минут.
OVERLAP = timedelta(minutes=5)

# Даём новым событиям 60 секунд
# для попадания в Wazuh Indexer.
INGEST_DELAY = timedelta(seconds=60)


def utc_string(value):
    return value.astimezone(timezone.utc).isoformat(
        timespec="milliseconds"
    ).replace("+00:00", "Z")


def init_sync_state():
    init_db()

    with closing(sqlite3.connect(DB_PATH)) as conn:
        with conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sync_state (
                    name TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )
            """)


def get_checkpoint():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        row = conn.execute(
            "SELECT value FROM sync_state WHERE name = ?",
            (STATE_KEY,),
        ).fetchone()

    if row is None:
        return None

    return datetime.fromisoformat(
        row[0].replace("Z", "+00:00")
    )


def save_checkpoint(value):
    with closing(sqlite3.connect(DB_PATH)) as conn:
        with conn:
            conn.execute("""
                INSERT INTO sync_state (name, value)
                VALUES (?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    value = excluded.value
            """, (
                STATE_KEY,
                utc_string(value),
            ))


def run_sync():
    init_sync_state()

    now = datetime.now(timezone.utc)
    end_time = now - INGEST_DELAY

    checkpoint = get_checkpoint()

    if checkpoint is None:
        start_time = end_time - INITIAL_LOOKBACK

        logger.info(
            "First synchronization: previous 24 hours"
        )
    else:
        start_time = checkpoint - OVERLAP

    if start_time >= end_time:
        logger.info("Nothing to synchronize yet")
        return

    start = utc_string(start_time)
    end = utc_string(end_time)

    logger.info(
        "Synchronization range: %s to %s",
        start,
        end,
    )

    client = WazuhClient()

    offset = 0
    received = 0
    added = 0

    while True:
        page = client.get_alerts_page(
            start_time=start,
            end_time=end,
            offset=offset,
            page_size=PAGE_SIZE,
        )

        total = page["total"]

        if total > MAX_RESULTS:
            raise RuntimeError(
                f"Found {total} alerts in the window. "
                f"Maximum allowed: {MAX_RESULTS}. "
                "Checkpoint will not be updated."
            )

        alerts = page["alerts"]

        if not alerts:
            if offset < total:
                raise RuntimeError(
                    "Empty page before synchronization finished"
                )

            break

        new_count = save_alerts(alerts)

        added += new_count
        received += len(alerts)
        offset += len(alerts)

        logger.info(
            "Processed %d/%d alerts. New: %d",
            received,
            total,
            added,
        )

        if offset >= total:
            break

    # Сохраняем контрольную отметку только
    # после успешной обработки всех страниц.
    save_checkpoint(end_time)

    logger.info(
        "Synchronization completed. "
        "Received=%d New=%d Duplicates=%d",
        received,
        added,
        received - added,
    )


if __name__ == "__main__":
    try:
        run_sync()
    except Exception:
        logger.exception("Synchronization failed")
        raise SystemExit(1)

