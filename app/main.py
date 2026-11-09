from pathlib import Path

from fastapi import FastAPI
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.staticfiles import StaticFiles

import os
import secrets

import requests
from dotenv import load_dotenv
from fastapi import Header, HTTPException

from app.services.wazuh import WazuhClient

from typing import Literal
from pydantic import BaseModel

from app.services.database import (
    save_alerts,
    get_incidents,
    update_incident_status,
)

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

app = FastAPI(
    title="Bazaru Jackson SOAR",
    description="Security Orchestration, Automation and Response",
    version="0.1.0",
    docs_url=None,
)

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static",
)


@app.get("/docs", include_in_schema=False)
def swagger_docs():
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=f"{app.title} - Swagger UI",
        swagger_js_url="/static/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui.css",
    )


@app.get("/")
def home():
    return {
        "application": "Bazaru Jackson SOAR",
        "status": "running",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/api/alerts")
def get_alerts(
    x_soar_token: str = Header(default=""),
    min_level: int = 7,
    limit: int = 20,
):
    expected_token = os.environ.get("SOAR_API_TOKEN", "")

    if not expected_token or not secrets.compare_digest(
        x_soar_token, expected_token
    ):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
        )

    if not 7 <= min_level <= 16 or not 1 <= limit <= 100:
        raise HTTPException(
            status_code=400,
            detail="Invalid query parameters",
        )

    try:
        client = WazuhClient()
        return client.get_alerts(
            min_level=min_level,
            limit=limit,
        )
    except (requests.RequestException, ValueError, KeyError):
        raise HTTPException(
            status_code=502,
            detail="Wazuh Indexer request failed",
        )


def verify_soar_token(token: str):
    expected = os.environ.get("SOAR_API_TOKEN", "")

    if not expected or not secrets.compare_digest(
        token, expected
    ):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
        )


class StatusUpdate(BaseModel):
    status: Literal["new", "in_progress", "closed"]


@app.post("/api/sync")
def sync_alerts(x_soar_token: str = Header(default="")):
    verify_soar_token(x_soar_token)

    try:
        client = WazuhClient()
        result = client.get_alerts(min_level=7, limit=100)
    except (requests.RequestException, ValueError, KeyError):
        raise HTTPException(
            status_code=502,
            detail="Wazuh Indexer request failed",
        )

    try:
        added = save_alerts(result["alerts"])
    except (OSError, ValueError, KeyError) as exc:
        raise HTTPException(
            status_code=500,
            detail="Failed to save imported alerts",
        ) from exc

    return {
        "status": "success",
        "received": len(result["alerts"]),
        "new_alerts": added,
        "duplicates": len(result["alerts"]) - added,
    }


@app.get("/api/incidents")
def list_incidents(
    x_soar_token: str = Header(default=""),
    limit: int = 50,
):
    verify_soar_token(x_soar_token)

    if not 1 <= limit <= 100:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 100",
        )

    return {
        "incidents": get_incidents(limit)
    }


@app.patch("/api/incidents/{incident_id}/status")
def change_incident_status(
    incident_id: int,
    payload: StatusUpdate,
    x_soar_token: str = Header(default=""),
):
    verify_soar_token(x_soar_token)

    updated = update_incident_status(
        incident_id,
        payload.status,
    )

    if not updated:
        raise HTTPException(
            status_code=404,
            detail="Incident not found",
        )

    return {
        "id": incident_id,
        "status": payload.status,
    }

