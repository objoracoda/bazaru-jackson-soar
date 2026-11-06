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

