"""ShadowMesh reviewer dashboard.

Run from the repository root:
    streamlit run dashboard/app.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any

import pandas as pd
import requests
import streamlit as st
from dotenv import load_dotenv

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from dashboard.logic import (  # noqa: E402
    BAIT_FILES,
    classify_session,
    explain_action,
    explain_command,
    explain_event_type,
    safe_preview,
)

load_dotenv(ROOT_DIR / ".env")

COMPOSE_FILE = ROOT_DIR / "infra" / "docker-compose.yml"


ES_URL = os.getenv("DASHBOARD_ES_URL", "http://localhost:9200")

def _init_page() -> None:
    st.set_page_config(
        page_title="ShadowMesh Control Room",
        page_icon="SM",
        layout="wide",
    )
    st.markdown(
        """
        <style>
        :root {
            --sm-ink: #071015;
            --sm-panel: rgba(10, 23, 30, 0.84);
            --sm-panel-strong: rgba(8, 19, 25, 0.96);
            --sm-line: rgba(148, 163, 184, 0.18);
            --sm-line-bright: rgba(94, 234, 212, 0.42);
            --sm-mint: #5eead4;
            --sm-cyan: #67e8f9;
            --sm-amber: #fbbf24;
            --sm-coral: #fb7185;
            --sm-text: #ecfeff;
            --sm-muted: #9fb2b6;
        }
        .stApp {
            background-color: var(--sm-ink);
            background-image:
                linear-gradient(rgba(94, 234, 212, 0.035) 1px, transparent 1px),
                linear-gradient(90deg, rgba(94, 234, 212, 0.035) 1px, transparent 1px);
            background-size: 32px 32px;
            color: #eef7f6;
        }
        .block-container { padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1600px; }
        [data-testid="stSidebar"] { background: #08171d; border-right: 1px solid rgba(94, 234, 212, 0.14); }
        [data-testid="stSidebar"] > div:first-child { padding-top: 2rem; }
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] h3 { letter-spacing: 0.02em; color: var(--sm-text); }
        [data-testid="stSidebar"] [data-testid="stRadio"] label { color: #b8c9cc; }
        [data-testid="stSidebar"] [data-testid="stRadio"] label:hover { color: var(--sm-mint); }
        @keyframes shadowmesh-pulse {
            0%, 100% { box-shadow: 0 0 0 0 rgba(45, 212, 191, 0.16); }
            50% { box-shadow: 0 0 0 8px rgba(45, 212, 191, 0); }
        }
        @keyframes shadowmesh-rise {
            from { opacity: 0; transform: translateY(8px); }
            to { opacity: 1; transform: translateY(0); }
        }
        @keyframes shadowmesh-scan {
            0% { transform: translateX(-120%); opacity: 0; }
            18%, 72% { opacity: 0.5; }
            100% { transform: translateX(420%); opacity: 0; }
        }
        @keyframes shadowmesh-orbit {
            from { transform: rotateX(66deg) rotateZ(0deg); }
            to { transform: rotateX(66deg) rotateZ(360deg); }
        }
        @keyframes shadowmesh-orbit-reverse {
            from { transform: rotateY(64deg) rotateZ(360deg); }
            to { transform: rotateY(64deg) rotateZ(0deg); }
        }
        .hero-shell {
            position: relative;
            overflow: hidden;
            border: 1px solid var(--sm-line-bright);
            border-radius: 18px;
            padding: 26px 28px 20px;
            background: rgba(7, 16, 21, 0.94);
            box-shadow: 0 18px 52px rgba(0, 0, 0, 0.26), inset 0 1px 0 rgba(255, 255, 255, 0.04);
            animation: shadowmesh-rise 500ms ease-out both;
        }
        .hero-shell::before {
            content: "";
            position: absolute;
            inset: 0;
            pointer-events: none;
            background: repeating-linear-gradient(0deg, transparent 0 5px, rgba(255,255,255,0.012) 6px);
            opacity: 0.45;
        }
        .hero-scanline {
            position: absolute;
            left: 0;
            top: 0;
            width: 24%;
            height: 1px;
            background: linear-gradient(90deg, transparent, var(--sm-mint), transparent);
            animation: shadowmesh-scan 7s ease-in-out infinite;
        }
        .hero-layout { position: relative; display: grid; grid-template-columns: minmax(0, 1fr) 190px; gap: 28px; align-items: center; }
        .hero-kicker {
            color: var(--sm-mint);
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0;
            text-transform: uppercase;
        }
        .hero-title {
            color: #f0fdfa;
            font-size: 3.25rem;
            line-height: 1;
            margin: 8px 0 12px;
            font-weight: 800;
        }
        .hero-copy { color: #b8c9cc; max-width: 780px; font-size: 1rem; line-height: 1.65; }
        .hero-status { color: var(--sm-muted); font-size: 0.78rem; margin-top: 14px; }
        .hero-status strong { color: var(--sm-text); font-weight: 650; }
        .mesh-mark { position: relative; width: 168px; height: 168px; margin: auto; perspective: 700px; }
        .mesh-mark::before, .mesh-mark::after { content: ""; position: absolute; inset: 18px; border: 1px solid rgba(103, 232, 249, 0.26); transform: rotate(30deg) skewX(-12deg); }
        .mesh-mark::after { inset: 34px; border-color: rgba(251, 191, 36, 0.25); transform: rotate(-28deg) skewX(-12deg); }
        .mesh-ring { position: absolute; inset: 24px; border: 1px solid rgba(94, 234, 212, 0.62); border-radius: 50%; transform-style: preserve-3d; animation: shadowmesh-orbit 11s linear infinite; }
        .mesh-ring.reverse { inset: 38px; border-color: rgba(103, 232, 249, 0.54); animation: shadowmesh-orbit-reverse 8s linear infinite; }
        .mesh-ring::after { content: ""; position: absolute; width: 6px; height: 6px; top: 12px; left: 50%; border-radius: 50%; background: var(--sm-amber); box-shadow: 0 0 16px rgba(251,191,36,0.75); }
        .mesh-core { position: absolute; inset: 55px; display: grid; place-items: center; border: 1px solid rgba(240, 253, 250, 0.42); border-radius: 13px; color: var(--sm-text); font-size: 1.25rem; font-weight: 800; background: rgba(10, 35, 43, 0.84); box-shadow: 0 0 28px rgba(45,212,191,0.18), inset 0 0 18px rgba(103,232,249,0.1); transform: translateZ(30px); }
        .section-heading { display: flex; align-items: center; gap: 12px; margin: 28px 0 10px; }
        .section-index { display: grid; place-items: center; width: 28px; height: 28px; border: 1px solid rgba(94,234,212,0.45); border-radius: 8px; color: var(--sm-mint); font: 700 0.72rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; background: rgba(15, 50, 55, 0.54); }
        .section-kicker { color: var(--sm-mint); font: 700 0.65rem/1.2 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
        .section-title { color: var(--sm-text); font-size: 1.24rem; font-weight: 750; margin-top: 4px; }
        .section-heading + [data-testid="stCaptionContainer"] { margin-top: -4px; }
        .workspace-intro { margin: 18px 0 22px; padding-bottom: 15px; border-bottom: 1px solid var(--sm-line); }
        .workspace-title { color: var(--sm-text); font-size: 2rem; line-height: 1.1; font-weight: 760; margin-top: 5px; }
        .workspace-copy { color: var(--sm-muted); font-size: 0.9rem; margin-top: 8px; max-width: 650px; line-height: 1.5; }
        .story-board { border: 1px solid var(--sm-line); border-radius: 12px; background: rgba(8, 20, 27, 0.82); padding: 16px; margin-top: 10px; }
        .story-board-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 15px; }
        .story-board-title { color: var(--sm-text); font-weight: 720; font-size: 0.96rem; }
        .story-board-subtitle { color: var(--sm-muted); font-size: 0.74rem; margin-top: 3px; }
        .story-live { display: inline-flex; align-items: center; gap: 6px; color: var(--sm-mint); font: 700 0.65rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
        .story-live-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--sm-mint); animation: shadowmesh-pulse 1.8s infinite; }
        .story-live.done { color: var(--sm-muted); }
        .story-live.done .story-live-dot { background: var(--sm-muted); animation: none; }
        .story-track { display: grid; grid-template-columns: repeat(7, minmax(0, 1fr)); gap: 8px; position: relative; }
        .story-step { position: relative; min-height: 96px; border: 1px solid rgba(148,163,184,0.16); border-radius: 9px; padding: 10px; background: rgba(2,8,23,0.52); opacity: 0.58; transition: opacity 180ms ease, border-color 180ms ease, background 180ms ease, transform 180ms ease; }
        .story-step.complete { opacity: 1; border-color: rgba(45,212,191,0.45); background: rgba(13,64,67,0.28); }
        .story-step.active { opacity: 1; border-color: rgba(251,191,36,0.78); background: rgba(75,54,12,0.28); transform: translateY(-2px); box-shadow: 0 8px 20px rgba(0,0,0,0.16); }
        .story-step.future { opacity: 0.46; }
        .story-step-number { color: var(--sm-muted); font: 700 0.63rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .story-step.complete .story-step-number { color: var(--sm-mint); }
        .story-step.active .story-step-number { color: var(--sm-amber); }
        .story-step-label { color: var(--sm-text); font-size: 0.78rem; font-weight: 700; margin-top: 8px; }
        .story-step-copy { color: var(--sm-muted); font-size: 0.68rem; line-height: 1.35; margin-top: 4px; }
        .story-detail { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 12px; }
        .story-detail-box { border-left: 2px solid rgba(103,232,249,0.58); padding: 9px 11px; background: rgba(15,23,42,0.54); border-radius: 0 8px 8px 0; }
        .story-detail-label { color: var(--sm-cyan); font: 700 0.62rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
        .story-detail-text { color: #cbd5e1; font-size: 0.78rem; line-height: 1.4; margin-top: 5px; }
        .story-empty { color: var(--sm-muted); font-size: 0.78rem; padding: 10px 0 2px; }
        .status-orb {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            display: inline-block;
            margin-right: 8px;
            background: #fbbf24;
            animation: shadowmesh-pulse 2s infinite;
            vertical-align: -1px;
        }
        .status-orb.online { background: #2dd4bf; }
        .status-orb.offline { background: #fb7185; animation: none; }
        .pipeline {
            display: grid;
            grid-template-columns: repeat(6, minmax(0, 1fr));
            gap: 10px;
            margin: 12px 0 6px;
        }
        .pipeline-node {
            position: relative;
            min-height: 84px;
            padding: 14px 13px 12px;
            border: 1px solid var(--sm-line);
            border-radius: 12px;
            background: rgba(2, 8, 23, 0.7);
            animation: shadowmesh-rise 450ms ease-out both;
            transition: border-color 180ms ease, transform 180ms ease, background 180ms ease;
        }
        .pipeline-node:hover { border-color: rgba(103, 232, 249, 0.66); transform: translateY(-3px); background: rgba(10, 35, 43, 0.82); }
        .pipeline-node:not(:last-child)::after { content: ""; position: absolute; top: 50%; right: -11px; width: 10px; height: 1px; background: linear-gradient(90deg, var(--sm-mint), transparent); opacity: 0.72; }
        .pipeline-node.done { border-color: rgba(45, 212, 191, 0.58); background: rgba(13, 64, 67, 0.34); }
        .pipeline-node.current { border-color: rgba(251, 191, 36, 0.62); animation: shadowmesh-pulse 2.2s infinite; }
        .pipeline-index { color: var(--sm-mint); font: 700 0.68rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; }
        .pipeline-label { color: #ecfeff; font-weight: 700; margin-top: 7px; }
        .pipeline-state { color: #9fb2b6; font-size: 0.76rem; margin-top: 4px; }
        .signal-strip {
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin: 12px 0 4px;
        }
        .signal-chip {
            border: 1px solid rgba(148, 163, 184, 0.22);
            border-radius: 999px;
            padding: 6px 10px;
            color: #cbd5e1;
            background: rgba(15, 23, 42, 0.72);
            font-size: 0.78rem;
        }
        .signal-chip strong { color: #f0fdfa; }
        div[data-testid="stMetric"] {
            background: var(--sm-panel);
            border: 1px solid var(--sm-line);
            border-radius: 12px;
            padding: 14px 16px;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
            transition: border-color 180ms ease, transform 180ms ease;
        }
        div[data-testid="stMetric"]:hover { border-color: rgba(94,234,212,0.48); transform: translateY(-2px); }
        div[data-testid="stMetricLabel"] { color: var(--sm-muted); }
        div[data-testid="stMetricValue"] { color: var(--sm-text); }
        .status-card {
            border: 1px solid var(--sm-line);
            border-radius: 12px;
            padding: 16px;
            background: var(--sm-panel);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
            transition: border-color 180ms ease, transform 180ms ease;
        }
        .status-card:hover { border-color: rgba(103,232,249,0.46); transform: translateY(-2px); }
        .plain-box {
            border-left: 3px solid var(--sm-mint);
            padding: 12px 14px;
            border-radius: 8px;
            background: rgba(15, 23, 42, 0.72);
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.03);
        }
        div[data-testid="stButton"] button { border-radius: 9px; border: 1px solid rgba(148,163,184,0.24); background: rgba(15, 35, 42, 0.86); color: var(--sm-text); transition: transform 160ms ease, border-color 160ms ease, background 160ms ease; }
        div[data-testid="stButton"] button:hover { transform: translateY(-1px); border-color: var(--sm-mint); background: rgba(15, 55, 58, 0.9); }
        div[data-testid="stButton"] button[kind="primary"] { border-color: rgba(94,234,212,0.7); background: rgba(13, 96, 91, 0.84); }
        div[data-testid="stTextInput"] input, div[data-testid="stNumberInput"] input, div[data-testid="stSelectbox"] div[data-baseweb="select"] > div { background: rgba(7, 20, 27, 0.86); border-color: rgba(148,163,184,0.24); }
        div[data-testid="stExpander"] { border-color: var(--sm-line); border-radius: 10px; background: rgba(7, 20, 27, 0.42); }
        [data-testid="stDataFrame"] { border: 1px solid var(--sm-line); border-radius: 10px; overflow: hidden; }
        code { color: var(--sm-cyan); }
        @media (prefers-reduced-motion: reduce) { *, *::before, *::after { animation-duration: 0.001ms !important; animation-iteration-count: 1 !important; transition-duration: 0.001ms !important; } }
        @media (max-width: 900px) {
            .pipeline { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .pipeline-node:not(:last-child)::after { display: none; }
            .hero-layout { grid-template-columns: 1fr; }
            .mesh-mark { display: none; }
            .hero-title { font-size: 2.5rem; }
            .story-track { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .story-detail { grid-template-columns: 1fr; }
        }
        /* Deliberately quiet review layout: hierarchy comes from space, not more panels. */
        .block-container { max-width: 1320px; padding-top: 1.35rem; }
        .hero-shell { border-radius: 14px; padding: 22px 24px 18px; box-shadow: 0 12px 30px rgba(0,0,0,0.18); }
        .hero-layout { grid-template-columns: minmax(0, 1fr) 128px; gap: 22px; }
        .hero-kicker { font-size: 0.68rem; }
        .hero-title { font-size: 2.45rem; margin: 7px 0 9px; }
        .hero-copy { font-size: 0.92rem; line-height: 1.5; max-width: 700px; }
        .hero-status { margin-top: 10px; font-size: 0.74rem; }
        .mesh-mark { width: 116px; height: 116px; }
        .mesh-mark::before { inset: 12px; }
        .mesh-mark::after { inset: 24px; }
        .mesh-ring { inset: 17px; }
        .mesh-ring.reverse { inset: 27px; }
        .mesh-core { inset: 38px; border-radius: 9px; font-size: 0.9rem; }
        .signal-strip { gap: 6px; margin-top: 9px; }
        .signal-chip { padding: 4px 8px; font-size: 0.7rem; }
        .section-heading { margin: 20px 0 7px; gap: 9px; }
        .section-index { width: 24px; height: 24px; border-radius: 6px; }
        .section-kicker { font-size: 0.58rem; }
        .section-title { font-size: 1.05rem; margin-top: 2px; }
        .pipeline { gap: 7px; margin-top: 8px; }
        .pipeline-node { min-height: 72px; padding: 10px; border-radius: 9px; }
        .pipeline-label { font-size: 0.84rem; margin-top: 5px; }
        .pipeline-state { font-size: 0.68rem; line-height: 1.3; }
        div[data-testid="stMetric"] { border-radius: 9px; padding: 10px 12px; }
        div[data-testid="stMetricValue"] { font-size: 1.22rem; }
        .status-card { border-radius: 9px; padding: 12px; }
        .plain-box { padding: 10px 12px; }
        [data-testid="stSidebar"] { background: rgba(8, 23, 29, 0.96); }
        [data-testid="stSidebar"] .stDivider { margin: 0.65rem 0; }
        </style>
        """,
        unsafe_allow_html=True,
    )


def es_request(method: str, path: str, **kwargs: Any) -> tuple[bool, dict[str, Any]]:
    """Call Elasticsearch and return a safe success/data tuple."""
    try:
        response = requests.request(
            method,
            f"{ES_URL.rstrip('/')}/{path.lstrip('/')}",
            timeout=4,
            **kwargs,
        )
        if response.status_code >= 400:
            return False, {"error": response.text}
        return True, response.json()
    except requests.RequestException as exc:
        return False, {"error": str(exc)}


def search_index(index: str, *, size: int = 10, query: dict | None = None) -> list[dict]:
    body = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": query or {"match_all": {}},
    }
    ok, data = es_request("POST", f"{index}/_search", json=body)
    if not ok:
        return []
    return [hit.get("_source", {}) for hit in data.get("hits", {}).get("hits", [])]


def _project_python() -> str:
    """Choose a project virtualenv before falling back to the dashboard runtime."""
    for candidate in (ROOT_DIR / ".venv" / "bin" / "python", ROOT_DIR / ".venv311" / "bin" / "python"):
        if candidate.exists():
            return str(candidate)
    return sys.executable


def _display(value: object, fallback: str = "-") -> str:
    """Return escaped, readable text for dashboard HTML fragments."""
    if value is None or value == "":
        return fallback
    return escape(str(value))


def run_command(
    command: list[str],
    *,
    timeout: int = 120,
    env_overrides: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Run a local project command for demo control buttons."""
    env = os.environ.copy()
    if env_overrides:
        env.update(env_overrides)

    try:
        completed = subprocess.run(
            command,
            cwd=ROOT_DIR,
            env=env,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)

    output = "\n".join(
        part for part in [completed.stdout.strip(), completed.stderr.strip()] if part
    )
    return completed.returncode == 0, output or "Command completed."


def _attack_command(profile: str, sessions: int) -> list[str]:
    return [
        "docker",
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "--profile",
        "attack",
        "run",
        "--rm",
        "-e",
        "POST_LOGIN_INITIAL_DELAY_SECONDS=0.5",
        "attacker",
        "python",
        "simulate.py",
        "--profile",
        profile,
        "--sessions",
        str(sessions),
        "--delay",
        "0.5",
    ]


def _attack_running() -> bool:
    active_attack = st.session_state.get("active_attack")
    if not active_attack:
        return False
    process = active_attack.get("process")
    if process is None:
        return False
    if process.poll() is None:
        return True
    active_attack["returncode"] = process.returncode
    active_attack["finished_at"] = datetime.now(timezone.utc).isoformat()
    return False


def _start_attack(profile: str, sessions: int) -> tuple[bool, str]:
    """Launch the simulator asynchronously so the visual story can advance live."""
    if _attack_running():
        return False, "An attack simulation is already running."

    baseline = search_index("honeypot-sessions", size=30)
    command = _attack_command(profile, sessions)
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT_DIR,
            env=os.environ.copy(),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        return False, str(exc)

    started_at = datetime.now(timezone.utc).isoformat()
    st.session_state["active_attack"] = {
        "process": process,
        "profile": profile,
        "sessions": sessions,
        "started_at": started_at,
        "baseline_session_ids": {
            str(item.get("session_id")) for item in baseline if item.get("session_id")
        },
    }
    return True, f"Attack simulation launched ({profile}, {sessions} session(s))."


def _attack_sessions() -> list[dict]:
    """Return sessions created during the current demo, newest first."""
    active_attack = st.session_state.get("active_attack")
    if not active_attack:
        return []
    started_at = active_attack["started_at"]
    docs = search_index(
        "honeypot-sessions",
        size=20,
        query={"range": {"@timestamp": {"gte": started_at}}},
    )
    baseline = active_attack.get("baseline_session_ids", set())
    return [item for item in docs if str(item.get("session_id")) not in baseline]


def _session_events(session_id: str | None) -> list[dict]:
    if not session_id:
        return []
    return search_index(
        "honeypot-cowrie-events",
        size=40,
        query={"term": {"session_id": session_id}},
    )


def _story_state(session: dict | None, events: list[dict]) -> dict[str, Any]:
    """Translate live telemetry into a reviewer-friendly story phase."""
    session = session or {}
    event_types = {str(event.get("event_type") or "") for event in events}
    commands = [str(command).lower() for command in session.get("commands", []) or []]
    joined = " ".join(commands)
    action_docs = search_index(
        "honeypot-rl-actions",
        size=8,
        query={"term": {"session_id": session.get("session_id", "")}},
    )
    rule_docs = search_index(
        "honeypot-generated-rules",
        size=8,
        query={"term": {"session_id": session.get("session_id", "")}},
    )

    stages = [
        ("01", "Launch", "The simulator is preparing a repeatable attacker profile."),
        ("02", "Connect", "The attacker reaches the fake SSH service."),
        ("03", "Credentials", "The decoy records the login attempts."),
        ("04", "Access", "A successful login opens the fake shell."),
        ("05", "Reconnaissance", "Commands reveal what the attacker is looking for."),
        ("06", "Bait interaction", "The attacker touches a believable fake secret."),
        ("07", "Adaptation", "The agent chooses a response to extend the engagement."),
        ("08", "Detection", "The observed behaviour becomes generated rule evidence."),
    ]
    active_attack = st.session_state.get("active_attack")
    complete = [
        bool(active_attack and active_attack.get("started_at")),
        bool("cowrie.session.connect" in event_types or session),
        bool("cowrie.login.failed" in event_types or session.get("login_attempts", 0) or session.get("login_success") or session.get("command_count", 0)),
        bool("cowrie.login.success" in event_types or session.get("login_success") or session.get("command_count", 0)),
        bool(commands or "cowrie.command.input" in event_types),
        bool(any(marker in joined for marker in ("/etc/passwd", "/etc/shadow", ".env", "id_rsa", "bash_history", "config.php"))),
        bool(action_docs),
        bool(rule_docs),
    ]
    active = next((index for index, done in enumerate(complete) if not done), len(complete) - 1)
    running = _attack_running()
    finished = bool(active_attack and active_attack.get("returncode") is not None)
    if finished and all(complete[:-1]):
        active = 7 if not complete[7] else 7

    if not session:
        current_detail = "Waiting for the first connection event from the simulator."
        observed = "No attacker telemetry yet. The journey is preloaded and will fill in as signals arrive."
    elif active == 1:
        current_detail = "The fake SSH endpoint has received the connection."
        observed = "Cowrie has started the decoy session."
    elif active == 2:
        current_detail = "The attacker is testing credentials against the decoy."
        observed = f"{session.get('login_attempts', 0)} login attempt(s) recorded so far."
    elif active == 3:
        current_detail = "The attacker is inside the fake shell."
        observed = "A successful login or command signal has opened the post-login phase."
    elif active == 4:
        current_detail = "The attacker is exploring the fake machine."
        observed = f"{session.get('command_count', 0)} command(s) captured so far."
    elif active == 5:
        current_detail = "The attacker has reached a high-value deception artifact."
        observed = "A bait path such as /etc/passwd, /etc/shadow, .env, or id_rsa was observed."
    elif active == 6:
        current_detail = "The adaptive layer is evaluating the session and recording its decision."
        observed = "The next signal is an agent action linked to this session."
    elif active == 7:
        current_detail = "Detection output is being linked back to the observed behaviour."
        observed = f"{len(rule_docs)} generated rule record(s) linked to this session."
    else:
        current_detail = "The review journey is ready to begin."
        observed = "Run an attack profile to populate the live story."

    return {
        "stages": stages,
        "complete": complete,
        "active": active,
        "running": running,
        "finished": finished,
        "session": session,
        "events": events,
        "action_docs": action_docs,
        "rule_docs": rule_docs,
        "current_detail": current_detail,
        "observed": observed,
    }


def render_story_board() -> dict:
    """Render the always-present visual narrative, even before telemetry exists."""
    sessions = _attack_sessions()
    latest = sessions[0] if sessions else None
    events = _session_events(latest.get("session_id")) if latest else []
    state = _story_state(latest, events)
    status_label = "Live signal" if state["running"] else ("Journey complete" if state["finished"] else "Ready for a run")
    status_class = "" if state["running"] else "done"
    step_markup = []
    for index, ((number, label, copy), done) in enumerate(zip(state["stages"], state["complete"])):
        css_state = "complete" if done and index < state["active"] else ("active" if index == state["active"] else "future")
        step_markup.append(
            f"<div class='story-step {css_state}'><div class='story-step-number'>{number}</div>"
            f"<div class='story-step-label'>{_display(label)}</div><div class='story-step-copy'>{_display(copy)}</div></div>"
        )
    st.markdown(
        f"""
        <div class="story-board">
          <div class="story-board-head">
            <div><div class="story-board-title">The attack journey</div><div class="story-board-subtitle">A visual explanation of what the system is doing right now.</div></div>
            <div class="story-live {status_class}"><span class="story-live-dot"></span>{status_label}</div>
          </div>
          <div class="story-track">{''.join(step_markup)}</div>
          <div class="story-detail">
            <div class="story-detail-box"><div class="story-detail-label">Current moment</div><div class="story-detail-text">{_display(state['current_detail'])}</div></div>
            <div class="story-detail-box"><div class="story-detail-label">What the reviewer can see</div><div class="story-detail-text">{_display(state['observed'])}</div></div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if latest:
        attack_label, explanation = classify_session(latest)
        cols = st.columns([2.2, 1, 1, 1])
        cols[0].metric("Attack type", attack_label)
        cols[1].metric("Login attempts", latest.get("login_attempts", 0))
        cols[2].metric("Commands", latest.get("command_count", 0))
        cols[3].metric("Session", "Active" if latest.get("session_active") else "Closed")
        st.markdown(f"<div class='plain-box'><b>In plain English:</b> {_display(explanation)}</div>", unsafe_allow_html=True)
    else:
        st.markdown("<div class='story-empty'>The visual journey is already loaded. Run an attack profile and the highlighted step will advance as the live services report each moment.</div>", unsafe_allow_html=True)
    return latest or {}


def render_live_story() -> None:
    """Refresh the narrative once a second while an attack is active."""
    fragment = getattr(st, "fragment", None)
    if fragment is None:
        render_story_board()
        return

    @fragment(run_every="1s")
    def _story_fragment() -> None:
        latest = render_story_board()
        render_story(latest)

    _story_fragment()


def docker_services() -> list[dict[str, Any]]:
    command = [
        "docker",
        "compose",
        "-f",
        str(COMPOSE_FILE),
        "ps",
        "--format",
        "json",
    ]
    ok, output = run_command(command, timeout=20)
    if not ok:
        return []

    services = []
    for line in output.splitlines():
        try:
            services.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return services


def render_header() -> None:
    st.markdown(
        """
        <section class="hero-shell">
        <span class="hero-scanline"></span>
        <div class="hero-layout">
          <div>
            <div class="hero-kicker">ShadowMesh / Unified Demonstration Layer</div>
            <div class="hero-title">Control Room</div>
            <div class="hero-copy">One clear story from attacker behaviour to adaptive deception and detection output. The services stay independent underneath; the reviewer sees the whole system here.</div>
            <div class="hero-status"><span class="status-orb online"></span><strong>Review mode ready</strong> · telemetry, deception, and detection are connected</div>
            <div class="signal-strip">
              <span class="signal-chip"><strong>6</strong> connected layers</span>
              <span class="signal-chip"><strong>SSH</strong> deception target</span>
              <span class="signal-chip"><strong>AI</strong> bait artifacts</span>
              <span class="signal-chip"><strong>Snort + YARA</strong> output</span>
            </div>
          </div>
          <div class="mesh-mark" aria-label="ShadowMesh six-layer mesh emblem">
            <div class="mesh-ring"></div><div class="mesh-ring reverse"></div><div class="mesh-core">SM</div>
          </div>
        </div>
        </section>
        """,
        unsafe_allow_html=True,
    )


def render_demo_walkthrough() -> None:
    st.markdown('<div class="section-heading"><span class="section-index">01</span><div><div class="section-kicker">System narrative</div><div class="section-title">The ShadowMesh Story</div></div></div>', unsafe_allow_html=True)
    st.caption("Follow the signal from the first connection to the final security artifact.")
    stages = [
        ("01", "Fake SSH", "Cowrie", "The decoy accepts the connection."),
        ("02", "Attack", "Simulator", "A repeatable profile creates behaviour."),
        ("03", "Telemetry", "Elasticsearch", "Events become a searchable story."),
        ("04", "Bait", "Generative layer", "Fake secrets make the target believable."),
        ("05", "Adaptation", "Agent + executor", "The system chooses a deception move."),
        ("06", "Detection", "Rule generator", "Behaviour becomes Snort/YARA output."),
    ]
    nodes = []
    for index, (number, label, owner, state) in enumerate(stages):
        classes = "pipeline-node"
        nodes.append(
            f"<div class='{classes}' style='animation-delay:{index * 70}ms'>"
            f"<div class='pipeline-index'>{number}</div>"
            f"<div class='pipeline-label'>{label}</div>"
            f"<div class='pipeline-state'>{owner}<br/>{state}</div></div>"
        )
    st.markdown(f"<div class='pipeline'>{''.join(nodes)}</div>", unsafe_allow_html=True)


def render_status() -> None:
    st.markdown('<div class="section-heading"><span class="section-index">02</span><div><div class="section-kicker">Live service fabric</div><div class="section-title">System Status</div></div></div>', unsafe_allow_html=True)
    ok, health = es_request("GET", "_cluster/health")
    services = docker_services()
    running = {
        item.get("Service") or item.get("Name"): item.get("State") or item.get("Status")
        for item in services
    }

    service_states = {
        "Elasticsearch": "Online" if ok else "Offline",
        "Cowrie": _service_state(running, "cowrie"),
        "Forwarder": _service_state(running, "forwarder"),
        "Agent": _service_state(running, "agent-runner"),
        "Executor": _service_state(running, "action-executor"),
        "Kibana": _service_state(running, "kibana"),
    }
    cols = st.columns(len(service_states))
    for column, (label, state) in zip(cols, service_states.items()):
        column.metric(label, state)

    if ok:
        st.caption(f"Elasticsearch cluster status: {health.get('status', 'unknown')}")
    else:
        st.warning("Elasticsearch is not reachable yet. Start the stack first. The dashboard is still usable in review mode.")

    if running:
        active = sum("running" in str(state).lower() for state in running.values())
        st.caption(f"Docker reports {active} running service(s). Refresh the page after starting the stack to update this signal.")
    else:
        st.caption("Docker has not reported any ShadowMesh services yet.")


def _service_state(running: dict[str, str], service: str) -> str:
    state = running.get(service) or running.get(f"infra-{service}-1")
    if not state:
        return "Not seen"
    return "Running" if "running" in state.lower() else state


def render_sidebar() -> str:
    """Provide a quiet review navigation rail without duplicating page content."""
    with st.sidebar:
        st.markdown("### ShadowMesh")
        st.caption("Control Room")
        view = st.radio(
            "Workspace",
            ["Mission Control", "Evidence Lab", "Bait Studio", "Rules Lab"],
            label_visibility="collapsed",
        )
        st.divider()
        st.caption("A single review layer over the independent ShadowMesh services.")
        st.markdown("#### External tools")
        st.link_button("Open Kibana", "http://localhost:5601", width="stretch")
        st.link_button("Open Elasticsearch", ES_URL, width="stretch")
    return view


def render_controls() -> None:
    st.markdown('<div class="section-heading"><span class="section-index">03</span><div><div class="section-kicker">Operator actions</div><div class="section-title">Demo Controls</div></div></div>', unsafe_allow_html=True)
    st.caption("Start one review scenario here. The supporting maintenance actions stay available below.")
    profile_col, sessions_col, run_col = st.columns([1.1, 0.7, 1.2])
    with profile_col:
        profile = st.selectbox(
            "Attack profile",
            ["opportunist", "scriptkiddie", "targeted"],
            help="Opportunist is best for review because it shows login, recon, bait, and payload attempt.",
        )
    with sessions_col:
        sessions = st.number_input("Sessions", min_value=1, max_value=10, value=1)
    with run_col:
        if st.button("Run Attack Simulation", width="stretch"):
            ok, output = _start_attack(profile, int(sessions))
            _remember_command(f"Run {profile} attack", ok, output)

    with st.expander("Stack and artifact maintenance"):
        start_col, stop_col, bait_col, rules_col = st.columns(4)
        with start_col:
            rebuild = st.checkbox("Rebuild images", value=False, help="Only enable this when source or dependency files changed.")
            if st.button("Start / Refresh Stack", width="stretch"):
                compose_action = ["up", "-d"]
                if rebuild:
                    compose_action.append("--build")
                ok, output = run_command(
                    ["docker", "compose", "-f", str(COMPOSE_FILE), *compose_action],
                    timeout=300 if rebuild else 120,
                )
                _remember_command("Start stack", ok, output)
        with stop_col:
            if st.button("Stop Stack", width="stretch"):
                ok, output = run_command(
                    ["docker", "compose", "-f", str(COMPOSE_FILE), "stop"],
                    timeout=90,
                )
                _remember_command("Stop stack", ok, output)
        with bait_col:
            if st.button("Regenerate AI Bait", width="stretch"):
                ok, output = run_command(
                    [_generative_python(), "generative/generator.py"],
                    timeout=240,
                )
                _remember_command("Regenerate AI bait", ok, output)
        with rules_col:
            if st.button("Generate Rules", width="stretch"):
                ok, output = run_command(
                    [_project_python(), "-m", "rules.generator", "--limit", "1"],
                    timeout=120,
                    env_overrides={"ES_HOST": "localhost", "ES_PORT": "9200"},
                )
                _remember_command("Generate rules", ok, output)

    if "last_command" in st.session_state:
        label, ok, output = st.session_state["last_command"]
        if ok:
            st.success(f"{label}: completed")
        else:
            st.error(f"{label}: failed")
        with st.expander("Command output"):
            st.code(output, language="text")


def _remember_command(label: str, ok: bool, output: str) -> None:
    st.session_state["last_command"] = (label, ok, output)


def _generative_python() -> str:
    venv_python = ROOT_DIR / "generative" / "venv" / "bin" / "python"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def render_live_overview(sessions: list[dict]) -> dict:
    """Show the current session as a single reviewer-friendly control signal."""
    st.markdown('<div class="section-heading"><span class="section-index">04</span><div><div class="section-kicker">Behaviour signal</div><div class="section-title">Live Attack Overview</div></div></div>', unsafe_allow_html=True)
    if not sessions:
        st.info("No live session has reached Elasticsearch yet. The review path is ready; run an attack from Demo Controls.")
        return {}

    options = [
        f"{item.get('session_id', 'unknown')} · {item.get('command_count', 0)} commands · {_short_time(item.get('@timestamp'))}"
        for item in sessions
    ]
    selected_index = st.selectbox("Session focus", range(len(sessions)), format_func=lambda index: options[index])
    latest = sessions[selected_index]
    attack_label, explanation = classify_session(latest)
    cols = st.columns([2.2, 1, 1, 1])
    cols[0].metric("Attack type", attack_label)
    cols[1].metric("Login attempts", latest.get("login_attempts", 0))
    cols[2].metric("Commands", latest.get("command_count", 0))
    cols[3].metric("Session", "Active" if latest.get("session_active") else "Closed")
    st.markdown(
        f"<div class='plain-box'><b>Plain English:</b> {_display(explanation)}</div>",
        unsafe_allow_html=True,
    )
    return latest


def render_story(latest: dict) -> None:
    """Render event telemetry for the selected session."""
    if not latest:
        return
    events = search_index(
        "honeypot-cowrie-events",
        size=18,
        query={"term": {"session_id": latest.get("session_id", "")}},
    )
    st.markdown("#### Attacker timeline")
    if not events:
        st.caption("This session summary exists, but its normalized event documents have not arrived yet.")
        return
    rows = []
    for event in reversed(events):
        rows.append(
            {
                "Time": _short_time(event.get("@timestamp")),
                "Event": event.get("event_type"),
                "What it means": explain_event_type(event.get("event_type")),
                "Command": event.get("command") or "-",
                "Command explanation": explain_command(event.get("command")),
            }
        )
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)


def render_adaptive_actions() -> None:
    st.markdown('<div class="section-heading"><span class="section-index">05</span><div><div class="section-kicker">Agent response</div><div class="section-title">Adaptive actions</div></div></div>', unsafe_allow_html=True)
    docs = search_index("honeypot-rl-actions", size=8)
    if not docs:
        st.info("No adaptive actions recorded yet. The agent will appear here after it observes a session.")
    for doc in docs:
        action = doc.get("action_name") or doc.get("action")
        st.markdown(
            f"""
            <div class="status-card">
            <b>{_display(action, "unknown action")}</b><br/>
            Session: <code>{_display(doc.get("session_id"), "unknown")}</code><br/>
            {_display(explain_action(action))}
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_generated_rule_records() -> None:
    st.markdown('<div class="section-heading"><span class="section-index">05</span><div><div class="section-kicker">Detection evidence</div><div class="section-title">Generated rule records</div></div></div>', unsafe_allow_html=True)
    docs = search_index("honeypot-generated-rules", size=5)
    if not docs:
        st.info("No rule records yet. Click Generate Rules after a session closes.")
    for doc in docs:
        ttps = doc.get("ttps_captured", [])
        st.markdown(
            f"""
            <div class="status-card">
            <b>{_display(doc.get("rule_count", 0))} rules generated</b><br/>
            Session: <code>{_display(doc.get("session_id"), "unknown")}</code><br/>
            TTPs captured: {_display(", ".join(ttps) if ttps else "not mapped")}
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_bait_files() -> None:
    st.markdown('<div class="section-heading"><span class="section-index">06</span><div><div class="section-kicker">Deception artifacts</div><div class="section-title">AI Bait Files</div></div></div>', unsafe_allow_html=True)
    selected = st.selectbox(
        "Bait artifact",
        BAIT_FILES,
        format_func=lambda item: f"{item.name}  ->  {item.attacker_path}",
    )
    absolute_path = ROOT_DIR / selected.local_path

    st.markdown(
        f"""
        <div class="plain-box">
        <b>Why this matters:</b> {selected.explanation}<br/>
        <b>Attacker sees:</b> <code>{selected.attacker_path}</code><br/>
        <b>Local source:</b> <code>{absolute_path}</code>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if absolute_path.exists():
        st.code(safe_preview(absolute_path.read_text(encoding="utf-8")), language="text")
    else:
        st.warning("Bait file not generated yet. Run `python generative/generator.py` first.")


def render_rule_files() -> None:
    st.markdown('<div class="section-heading"><span class="section-index">07</span><div><div class="section-kicker">Detection artifacts</div><div class="section-title">Rule Files On Disk</div></div></div>', unsafe_allow_html=True)
    output_root = ROOT_DIR / "rules" / "output"
    files = sorted(
        [path for path in output_root.rglob("*") if path.suffix in {".rules", ".yar"}],
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )
    if not files:
        st.info("No rule files found yet.")
        return

    selected = st.selectbox(
        "Rule artifact",
        files,
        format_func=lambda path: str(path.relative_to(ROOT_DIR)),
    )
    st.code(safe_preview(selected.read_text(encoding="utf-8")), language="text")


def _short_time(value: str | None) -> str:
    if not value:
        return "-"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc).strftime("%H:%M:%S UTC")
    except ValueError:
        return value


def main() -> None:
    _init_page()
    view = render_sidebar()
    render_header()

    if view == "Mission Control":
        render_demo_walkthrough()
        render_status()
        render_controls()
        render_live_story()
    elif view == "Evidence Lab":
        render_status()
        latest = render_live_overview(search_index("honeypot-sessions", size=12))
        render_story(latest)
        render_adaptive_actions()
    elif view == "Bait Studio":
        st.markdown('<div class="workspace-intro"><div class="section-kicker">Deception artifacts</div><div class="workspace-title">AI Bait Studio</div><div class="workspace-copy">Inspect the exact local artifact and the attacker-visible path it is mounted into.</div></div>', unsafe_allow_html=True)
        render_bait_files()
    else:
        st.markdown('<div class="workspace-intro"><div class="section-kicker">Detection artifacts</div><div class="workspace-title">Rules Lab</div><div class="workspace-copy">Review generated Snort and YARA artifacts, then trace them back to the attacker session.</div></div>', unsafe_allow_html=True)
        render_rule_files()
        render_generated_rule_records()

    st.caption(
        "Dashboard reads existing ShadowMesh services. It does not replace Cowrie, "
        "Elasticsearch, Kibana, the agent, or the rule generator."
    )


if __name__ == "__main__":
    main()
