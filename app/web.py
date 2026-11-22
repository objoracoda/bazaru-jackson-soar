"""Bazaru Jackson SOAR web UI: incident investigation, AI scoring, manual tuning drafts."""
import os
import secrets
from pathlib import Path

import requests
from fastapi import APIRouter, Form, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from app.services.ai import AIAnalysisError, analyze_incident, build_event_context, sanitize_context
from app.services.correlation import CorrelationError, build_correlated_context, find_related_alerts
from app.services.database import (
    add_incident_comment, get_incident, get_incident_history,
    get_incident_report, get_incidents, save_alerts,
    save_incident_report, update_incident_status,
)
from app.services.review_store import (
    create_snapshot, consume_snapshot, latest_review, save_review,
    similar_confirmed_fp, latest_proposal, save_proposal,
)
from app.services.tuning import TuningError, propose_exception
from app.services.wazuh import WazuhClient

router = APIRouter()
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / 'templates')
STATUSES = {'new', 'in_progress', 'closed'}


def authorized(request):
    return request.session.get('logged_in') is True


def require_auth(request):
    if not authorized(request):
        raise HTTPException(status_code=401, detail='Unauthorized')


def check_csrf(request, csrf_token):
    expected = request.session.get('csrf_token', '')
    if not expected or not secrets.compare_digest(csrf_token, expected):
        raise HTTPException(status_code=403, detail='Invalid CSRF token')


def load_raw_event(incident):
    try:
        event = WazuhClient().get_alert_document(incident['wazuh_index'], incident['wazuh_id'])
        return (event, None) if event is not None else (None, 'Исходный документ удалён из Indexer.')
    except (requests.RequestException, ValueError, KeyError):
        return None, 'Не удалось получить исходное событие Wazuh.'


def prepare_ai_context(incident, raw_event):
    if raw_event is None:
        return sanitize_context(build_event_context(incident))
    try:
        correlation = find_related_alerts(incident, raw_event)
        context = build_correlated_context(incident, raw_event, correlation)
    except (requests.RequestException, CorrelationError, KeyError, ValueError, RuntimeError, TypeError):
        context = build_event_context(incident, raw_event)
        context['correlation'] = {'status': 'unavailable', 'events': [], 'limitations': 'Корреляция недоступна; только исходный алерт.'}
    return sanitize_context(context)


def incident_page(request, incident_id, ai_result=None, ai_error=None, context=None, error=None):
    incident = get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail='Incident not found')
    raw, wazuh_error = load_raw_event(incident)
    if context is None:
        context = prepare_ai_context(incident, raw)
    # Signed session cookies stay small: the context lives in SQLite and the browser
    # receives only an opaque, expiring ID, not an untrusted JSON payload in a form.
    try:
        snapshot_id = create_snapshot(incident_id, request.session['csrf_token'], context)
    except ValueError:
        context = build_event_context(incident, raw)
        snapshot_id = create_snapshot(incident_id, request.session['csrf_token'], context)
        error = 'Контекст слишком большой: соседние алерты не попали в предпросмотр.'
    return templates.TemplateResponse(request, 'incident.html', {
        'incident': incident, 'report': get_incident_report(incident_id),
        'history': get_incident_history(incident_id),
        'raw_event': raw, 'wazuh_error': wazuh_error,
        'csrf_token': request.session['csrf_token'],
        'ai_context': context, 'snapshot_id': snapshot_id,
        'ai_result': ai_result, 'ai_error': ai_error or error,
        'review': latest_review(incident_id), 'tuning': latest_proposal(incident_id),
        'fp_count': similar_confirmed_fp(incident),
    })


@router.get('/login')
def login_page(request: Request):
    if authorized(request):
        return RedirectResponse('/panel', status_code=303)
    return templates.TemplateResponse(request, 'login.html', {'error': False})


@router.post('/login')
def login(request: Request, password: str = Form(...)):
    expected = os.environ['SOAR_WEB_PASSWORD']
    if not secrets.compare_digest(password, expected):
        return templates.TemplateResponse(request, 'login.html', {'error': True}, status_code=401)
    request.session.clear()
    request.session['logged_in'] = True
    request.session['csrf_token'] = secrets.token_urlsafe(32)
    return RedirectResponse('/panel', status_code=303)


@router.get('/panel')
def dashboard(request: Request, status: str = '', q: str = '', notice: str = ''):
    if not authorized(request):
        return RedirectResponse('/login', status_code=303)
    all_alerts = get_incidents(limit=100)
    counts = {'total': len(all_alerts),
              'new': sum(a['status'] == 'new' for a in all_alerts),
              'in_progress': sum(a['status'] == 'in_progress' for a in all_alerts),
              'closed': sum(a['status'] == 'closed' for a in all_alerts)}
    alerts = all_alerts
    if status in STATUSES:
        alerts = [a for a in alerts if a['status'] == status]
    if q:
        query = q.casefold()
        alerts = [a for a in alerts if query in ' '.join(str(a.get(key) or '') for key in ('agent', 'description', 'rule_id')).casefold()]
    return templates.TemplateResponse(request, 'dashboard.html', {
        'alerts': alerts, 'counts': counts, 'status_filter': status,
        'search': q, 'notice': notice, 'csrf_token': request.session['csrf_token'],
    })


@router.post('/panel/sync')
def sync_from_panel(request: Request, csrf_token: str = Form(...)):
    require_auth(request)
    check_csrf(request, csrf_token)
    try:
        result = WazuhClient().get_alerts(min_level=7, limit=100)
        added = save_alerts(result['alerts'])
    except (requests.RequestException, ValueError, KeyError):
        return RedirectResponse('/panel?notice=sync_error', status_code=303)
    return RedirectResponse(f'/panel?notice=imported_{added}', status_code=303)


@router.post('/panel/incidents/{incident_id}/status')
def update_status_from_panel(request: Request, incident_id: int, status: str = Form(...), csrf_token: str = Form(...)):
    require_auth(request)
    check_csrf(request, csrf_token)
    if status not in STATUSES:
        raise HTTPException(status_code=400, detail='Invalid status')
    if not update_incident_status(incident_id, status):
        raise HTTPException(status_code=404, detail='Incident not found')
    return RedirectResponse('/panel?notice=updated', status_code=303)


@router.post('/logout')
def logout(request: Request, csrf_token: str = Form(...)):
    require_auth(request)
    check_csrf(request, csrf_token)
    request.session.clear()
    return RedirectResponse('/login', status_code=303)


@router.get('/panel/incidents/{incident_id}')
def incident_detail(request: Request, incident_id: int):
    if not authorized(request):
        return RedirectResponse('/login', status_code=303)
    return incident_page(request, incident_id)


@router.post('/panel/incidents/{incident_id}/comment')
def create_incident_comment(request: Request, incident_id: int, comment: str = Form(...), csrf_token: str = Form(...)):
    require_auth(request)
    check_csrf(request, csrf_token)
    try:
        saved = add_incident_comment(incident_id, comment)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail='Invalid comment') from exc
    if not saved:
        raise HTTPException(status_code=404, detail='Incident not found')
    return RedirectResponse(f'/panel/incidents/{incident_id}', status_code=303)


@router.post('/panel/incidents/{incident_id}/set-status')
def set_incident_status_from_detail(request: Request, incident_id: int, status: str = Form(...), csrf_token: str = Form(...)):
    require_auth(request)
    check_csrf(request, csrf_token)
    if status not in STATUSES:
        raise HTTPException(status_code=400, detail='Invalid status')
    if not update_incident_status(incident_id, status):
        raise HTTPException(status_code=404, detail='Incident not found')
    return RedirectResponse(f'/panel/incidents/{incident_id}', status_code=303)


@router.post('/panel/incidents/{incident_id}/report')
def save_report_from_panel(request: Request, incident_id: int, description: str = Form(''), investigation: str = Form(''), verdict: str = Form('undetermined'), conclusion: str = Form(''), csrf_token: str = Form(...)):
    require_auth(request)
    check_csrf(request, csrf_token)
    try:
        saved = save_incident_report(incident_id, description, investigation, verdict, conclusion)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail='Invalid incident report') from exc
    if not saved:
        raise HTTPException(status_code=404, detail='Incident not found')
    return RedirectResponse(f'/panel/incidents/{incident_id}?saved=1', status_code=303)


@router.post('/panel/incidents/{incident_id}/ai-analyze')
def analyze_incident_from_panel(request: Request, incident_id: int, csrf_token: str = Form(...), snapshot_id: str = Form(...), consent: str = Form('')):
    require_auth(request)
    check_csrf(request, csrf_token)
    if consent != 'yes':
        raise HTTPException(status_code=400, detail='Explicit consent required')
    incident = get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail='Incident not found')
    # This is precisely the data previewed on GET, even if Indexer changes.
    context = consume_snapshot(snapshot_id, incident_id, csrf_token)
    if context is None:
        raise HTTPException(status_code=409, detail='Контекст устарел или уже использован. Обнови карточку и проверь данные ещё раз.')
    try:
        result = analyze_incident(incident, context=context)
        save_review(incident_id, context, result)
        return incident_page(request, incident_id, ai_result=result, context=context)
    except AIAnalysisError as exc:
        return incident_page(request, incident_id, ai_error=str(exc), context=context)


@router.post('/panel/incidents/{incident_id}/tuning')
def tuning_from_panel(request: Request, incident_id: int, rule_id: int = Form(...), csrf_token: str = Form(...)):
    require_auth(request)
    check_csrf(request, csrf_token)
    incident = get_incident(incident_id)
    if incident is None:
        raise HTTPException(status_code=404, detail='Incident not found')
    report = get_incident_report(incident_id)
    if not report or report['verdict'] != 'false_positive':
        raise HTTPException(status_code=403, detail='Сначала аналитик должен сохранить вердикт False Positive.')
    if similar_confirmed_fp(incident) < 3:
        raise HTTPException(status_code=403, detail='Для генерации нужно минимум 3 подтверждённых FP одного правила и агента.')
    raw, error = load_raw_event(incident)
    if raw is None:
        return incident_page(request, incident_id, ai_error=error)
    try:
        draft = propose_exception(incident, raw, rule_id)
        save_proposal(incident_id, draft['xml'], draft['rationale'])
    except TuningError as exc:
        return incident_page(request, incident_id, ai_error=str(exc))
    return RedirectResponse(f'/panel/incidents/{incident_id}#tuning', status_code=303)

