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
        page_title="ShadowMesh — Live Deception",
        page_icon="SM",
        layout="wide",
    )
    st.markdown(
        """
        <style>
        :root {
            --sm-ink: #0b0b0d;
            --sm-panel: rgba(22, 22, 25, 0.9);
            --sm-panel-strong: rgba(14, 14, 17, 0.97);
            --sm-line: rgba(239, 236, 226, 0.14);
            --sm-line-bright: rgba(201, 255, 90, 0.42);
            --sm-mint: #c9ff5a;
            --sm-cyan: #b9a7ff;
            --sm-amber: #ff784f;
            --sm-coral: #ff5c73;
            --sm-text: #f1eee6;
            --sm-muted: #96959c;
        }
        .stApp {
            background-color: var(--sm-ink);
            background-image:
                linear-gradient(rgba(239, 236, 226, 0.024) 1px, transparent 1px),
                linear-gradient(90deg, rgba(239, 236, 226, 0.024) 1px, transparent 1px);
            background-size: 32px 32px;
            color: #eef7f6;
        }
        .block-container { padding-top: 2.2rem; padding-bottom: 3rem; max-width: 1600px; }
        [data-testid="stSidebar"] { background: #101012; border-right: 1px solid rgba(239, 236, 226, 0.1); }
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
        /* Final palette pass: lime = ShadowMesh response, ember = intrusion, lavender = evidence. */
        [data-testid="stSidebar"] { background: #101012; border-right-color: rgba(239,236,226,0.1); }
        [data-testid="stSidebar"] [data-testid="stRadio"] label:hover { color: var(--sm-mint); }
        .hero-shell { border-color: rgba(201,255,90,0.34); background: #111113; }
        .hero-scanline { background: linear-gradient(90deg, transparent, var(--sm-mint), transparent); }
        .mesh-mark::before { border-color: rgba(201,255,90,0.22); }
        .mesh-mark::after { border-color: rgba(255,120,79,0.24); }
        .mesh-ring { border-color: rgba(201,255,90,0.52); }
        .mesh-ring.reverse { border-color: rgba(185,167,255,0.48); }
        .mesh-ring::after { background: var(--sm-amber); box-shadow: 0 0 16px rgba(255,120,79,0.68); }
        .mesh-core { border-color: rgba(241,238,230,0.38); background: #19191c; box-shadow: 0 0 28px rgba(201,255,90,0.12), inset 0 0 18px rgba(185,167,255,0.08); }
        .section-index { border-color: rgba(201,255,90,0.35); background: rgba(66,80,24,0.28); }
        .signal-chip { border-color: rgba(239,236,226,0.18); background: rgba(29,29,32,0.72); }
        div[data-testid="stButton"] button:hover { border-color: var(--sm-mint); background: rgba(66,80,24,0.45); }
        div[data-testid="stButton"] button[kind="primary"] { border-color: rgba(201,255,90,0.65); background: rgba(79,97,27,0.72); color: #f7f5ed; }
        code { color: var(--sm-cyan); }
        .cinema-stage {
            position: relative;
            overflow: hidden;
            min-height: 440px;
            margin-top: 18px;
            border: 1px solid rgba(148,163,184,0.2);
            border-radius: 18px;
            background: #060d12;
            box-shadow: 0 22px 70px rgba(0,0,0,0.34), inset 0 1px 0 rgba(255,255,255,0.04);
        }
        .cinema-stage::before {
            content: "";
            position: absolute;
            inset: 0;
            pointer-events: none;
            background-image: linear-gradient(rgba(103,232,249,0.035) 1px, transparent 1px), linear-gradient(90deg, rgba(103,232,249,0.035) 1px, transparent 1px);
            background-size: 36px 36px;
            mask-image: linear-gradient(to bottom, rgba(0,0,0,0.9), transparent 92%);
        }
        .cinema-stage::after {
            content: "";
            position: absolute;
            inset: 0;
            pointer-events: none;
            background: radial-gradient(circle at 52% 44%, rgba(20,184,166,0.08), transparent 30%), linear-gradient(110deg, transparent 0 46%, rgba(251,191,36,0.035) 50%, transparent 54%);
        }
        .cinema-chrome { position: relative; z-index: 3; display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 17px 19px 0; }
        .cinema-kicker { color: var(--sm-mint); font: 700 0.62rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
        .cinema-title { color: var(--sm-text); font-size: 1.08rem; font-weight: 760; margin-top: 6px; }
        .cinema-subtitle { color: var(--sm-muted); font-size: 0.73rem; margin-top: 3px; }
        .cinema-live { display: inline-flex; align-items: center; gap: 7px; border: 1px solid rgba(94,234,212,0.34); border-radius: 999px; padding: 7px 10px; color: var(--sm-mint); font: 700 0.63rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; background: rgba(13,64,67,0.22); }
        .cinema-live.idle { color: var(--sm-muted); border-color: rgba(148,163,184,0.22); background: rgba(15,23,42,0.34); }
        .cinema-live-dot { width: 7px; height: 7px; border-radius: 50%; background: currentColor; animation: shadowmesh-pulse 1.6s infinite; }
        .cinema-live.idle .cinema-live-dot { animation: none; }
        .cinema-canvas { position: relative; z-index: 2; height: 320px; margin: 10px 18px 0; }
        .cinema-floor { position: absolute; left: 4%; right: 4%; bottom: 12px; height: 68px; border-top: 1px solid rgba(103,232,249,0.1); transform: perspective(480px) rotateX(62deg); transform-origin: bottom; background-image: linear-gradient(rgba(103,232,249,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(103,232,249,0.05) 1px, transparent 1px); background-size: 34px 20px; opacity: 0.45; }
        .cinema-wire { position: absolute; z-index: 1; height: 2px; transform-origin: left center; background: rgba(148,163,184,0.16); transition: background 300ms ease, box-shadow 300ms ease; }
        .cinema-wire::after { content: ""; position: absolute; left: -3px; top: -3px; width: 8px; height: 8px; border-radius: 50%; background: var(--sm-mint); opacity: 0; box-shadow: 0 0 16px 3px rgba(94,234,212,0.78); }
        .cinema-wire.done { background: rgba(94,234,212,0.44); box-shadow: 0 0 10px rgba(94,234,212,0.12); }
        .cinema-wire.live { background: linear-gradient(90deg, rgba(251,191,36,0.75), rgba(94,234,212,0.28)); box-shadow: 0 0 15px rgba(251,191,36,0.2); }
        .cinema-wire.live::after { opacity: 1; animation: shadowmesh-packet 1.6s linear infinite; }
        @keyframes shadowmesh-packet { from { left: -3px; } to { left: calc(100% - 5px); } }
        .wire-1 { left: 16%; top: 51%; width: 12%; }
        .wire-2 { left: 36%; top: 51%; width: 12%; }
        .wire-3 { left: 56%; top: 48%; width: 13%; transform: rotate(-32deg); }
        .wire-4 { left: 70%; top: 40%; width: 1px; height: 19%; background: rgba(148,163,184,0.16); }
        .wire-4.done { background: rgba(94,234,212,0.44); }
        .wire-4.live { background: linear-gradient(to bottom, rgba(251,191,36,0.78), rgba(94,234,212,0.25)); }
        .wire-4::after { left: -3px; top: -3px; }
        .wire-4.live::after { animation-name: shadowmesh-packet-vertical; }
        @keyframes shadowmesh-packet-vertical { from { top: -3px; } to { top: calc(100% - 5px); } }
        .wire-5 { left: 77%; top: 68%; width: 12%; transform: rotate(-28deg); }
        .cinema-node { position: absolute; z-index: 2; width: 142px; min-height: 82px; padding: 11px 12px; border: 1px solid rgba(148,163,184,0.2); border-radius: 12px; background: rgba(8,19,25,0.92); box-shadow: 0 12px 22px rgba(0,0,0,0.22); transition: border-color 300ms ease, box-shadow 300ms ease, transform 300ms ease, opacity 300ms ease; }
        .cinema-node::before { content: ""; position: absolute; width: 9px; height: 9px; top: 12px; right: 12px; border-radius: 50%; background: rgba(148,163,184,0.38); }
        .cinema-node.complete { border-color: rgba(94,234,212,0.55); background: rgba(10,35,38,0.86); }
        .cinema-node.complete::before { background: var(--sm-mint); box-shadow: 0 0 13px rgba(94,234,212,0.65); }
        .cinema-node.current { border-color: rgba(251,191,36,0.82); transform: translateY(-5px) scale(1.03); box-shadow: 0 0 0 1px rgba(251,191,36,0.1), 0 16px 32px rgba(0,0,0,0.34), 0 0 28px rgba(251,191,36,0.12); }
        .cinema-node.current::before { background: var(--sm-amber); box-shadow: 0 0 15px rgba(251,191,36,0.8); animation: shadowmesh-pulse 1.4s infinite; }
        .cinema-node.future { opacity: 0.5; }
        .cinema-node.origin { left: 2%; top: 38%; }
        .cinema-node.decoy { left: 22%; top: 38%; }
        .cinema-node.telemetry { left: 42%; top: 38%; }
        .cinema-node.bait { left: 62%; top: 10%; }
        .cinema-node.agent { left: 62%; top: 68%; }
        .cinema-node.detection { left: 82%; top: 38%; }
        .cinema-node-type { color: var(--sm-mint); font: 700 0.57rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
        .cinema-node-name { color: var(--sm-text); font-size: 0.86rem; font-weight: 760; margin-top: 8px; }
        .cinema-node-copy { color: var(--sm-muted); font-size: 0.67rem; line-height: 1.35; margin-top: 4px; }
        .cinema-node-icon { position: absolute; left: 12px; bottom: -18px; width: 27px; height: 27px; border: 1px solid rgba(94,234,212,0.38); border-radius: 50%; background: #071015; box-shadow: 0 0 16px rgba(94,234,212,0.14); }
        .cinema-node-icon::before, .cinema-node-icon::after { content: ""; position: absolute; background: var(--sm-mint); opacity: 0.78; }
        .cinema-node-icon::before { left: 7px; right: 7px; top: 12px; height: 1px; }
        .cinema-node-icon::after { top: 7px; bottom: 7px; left: 12px; width: 1px; }
        .cinema-node.origin .cinema-node-icon { border-color: rgba(251,191,36,0.52); box-shadow: 0 0 18px rgba(251,191,36,0.16); }
        .cinema-node.origin .cinema-node-icon::before { left: 6px; right: 6px; top: 12px; transform: rotate(-35deg); background: var(--sm-amber); }
        .cinema-node.origin .cinema-node-icon::after { top: 6px; bottom: 6px; left: 12px; transform: rotate(35deg); background: var(--sm-amber); }
        .cinema-node.decoy .cinema-node-icon::before { left: 6px; right: 6px; top: 9px; box-shadow: 0 5px 0 rgba(94,234,212,0.78), 0 10px 0 rgba(94,234,212,0.44); }
        .cinema-node.decoy .cinema-node-icon::after { display: none; }
        .cinema-node.bait .cinema-node-icon { border-radius: 5px; }
        .cinema-node.bait .cinema-node-icon::before { left: 7px; right: 7px; top: 9px; box-shadow: 0 5px 0 rgba(94,234,212,0.42); }
        .cinema-node.bait .cinema-node-icon::after { top: 7px; bottom: 7px; left: auto; right: 7px; width: 6px; border-left: 1px solid var(--sm-mint); border-bottom: 1px solid var(--sm-mint); background: transparent; transform: rotate(-45deg); }
        .cinema-node.agent .cinema-node-icon { transform: rotate(45deg); border-radius: 7px; }
        .cinema-node.agent .cinema-node-icon::before, .cinema-node.agent .cinema-node-icon::after { transform: rotate(-45deg); }
        .cinema-node.detection .cinema-node-icon { border-radius: 4px; }
        .cinema-node.detection .cinema-node-icon::before { left: 6px; right: 6px; top: 9px; box-shadow: 0 6px 0 rgba(94,234,212,0.42); }
        .cinema-node.detection .cinema-node-icon::after { display: none; }
        .split-stage { position: relative; overflow: hidden; margin-top: 18px; border: 1px solid rgba(239,236,226,0.16); border-radius: 18px; background: #0c0c0e; box-shadow: 0 24px 70px rgba(0,0,0,0.42); }
        .split-stage::before { content: ""; position: absolute; inset: 0; pointer-events: none; background: radial-gradient(circle at 30% 50%, rgba(255,120,79,0.09), transparent 30%), radial-gradient(circle at 72% 50%, rgba(201,255,90,0.09), transparent 30%); }
        .split-head { position: relative; z-index: 2; display: flex; justify-content: space-between; align-items: center; padding: 17px 20px 0; }
        .split-head-title { color: var(--sm-text); font-size: 1.05rem; font-weight: 760; }
        .split-head-copy { color: var(--sm-muted); font-size: 0.72rem; margin-top: 4px; }
        .split-state { color: var(--sm-mint); font: 700 0.62rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
        .split-state.idle { color: var(--sm-muted); }
        .split-body { position: relative; z-index: 1; display: grid; grid-template-columns: 1fr 1px 1fr; min-height: 390px; padding: 22px 20px 18px; gap: 18px; }
        .split-divider { position: relative; background: linear-gradient(to bottom, transparent, rgba(239,236,226,0.22), transparent); }
        .split-divider::before { content: "DECOY BOUNDARY"; position: absolute; left: 50%; top: 50%; transform: translate(-50%,-50%) rotate(-90deg); white-space: nowrap; color: rgba(239,236,226,0.42); font: 700 0.56rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: 0.08em; }
        .split-pane { position: relative; display: flex; flex-direction: column; justify-content: center; min-width: 0; }
        .split-pane-label { color: var(--sm-muted); font: 700 0.62rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
        .split-pane-title { color: var(--sm-text); font-size: 1.45rem; font-weight: 760; margin-top: 7px; }
        .split-pane-copy { color: var(--sm-muted); max-width: 300px; font-size: 0.78rem; line-height: 1.45; margin-top: 7px; }
        .split-signal { position: relative; height: 148px; margin-top: 20px; }
        .split-track { position: absolute; left: 5%; right: 5%; top: 50%; height: 1px; background: rgba(239,236,226,0.16); }
        .split-track::before { content: ""; position: absolute; inset: -2px 0; background: linear-gradient(90deg, transparent, rgba(255,120,79,0.62), transparent); transform: scaleX(var(--signal-progress, 0)); transform-origin: left; transition: transform 500ms ease; }
        .split-packet { position: absolute; left: calc(5% + var(--signal-progress, 0) * 90%); top: calc(50% - 5px); width: 10px; height: 10px; border-radius: 50%; background: var(--sm-amber); box-shadow: 0 0 0 4px rgba(255,120,79,0.13), 0 0 22px rgba(255,120,79,0.72); transition: left 700ms cubic-bezier(.2,.8,.2,1); }
        .split-event { position: absolute; left: 5%; top: 16%; max-width: 180px; color: #ece8de; font-size: 0.76rem; line-height: 1.4; opacity: 0.92; }
        .split-event::before { content: "LATEST MOVE"; display: block; color: var(--sm-amber); font: 700 0.56rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; margin-bottom: 5px; }
        .split-steps { display: grid; grid-template-columns: repeat(4, 1fr); gap: 6px; margin-top: 10px; }
        .split-step { height: 3px; border-radius: 999px; background: rgba(239,236,226,0.12); }
        .split-step.done { background: var(--sm-amber); }
        .split-pane.right .split-track::before { background: linear-gradient(90deg, transparent, rgba(201,255,90,0.7), transparent); }
        .split-pane.right .split-packet { background: var(--sm-mint); box-shadow: 0 0 0 4px rgba(201,255,90,0.13), 0 0 22px rgba(201,255,90,0.7); }
        .split-pane.right .split-event::before { color: var(--sm-mint); }
        .split-footer { position: relative; z-index: 2; display: grid; grid-template-columns: 1fr 1fr; gap: 10px; padding: 0 20px 18px; }
        .split-note { border-top: 1px solid rgba(239,236,226,0.14); padding-top: 10px; color: var(--sm-muted); font-size: 0.72rem; line-height: 1.4; }
        .split-note strong { color: var(--sm-text); font-weight: 650; }
        @media (max-width: 900px) { .split-body { grid-template-columns: 1fr; gap: 24px; } .split-divider { height: 1px; } .split-divider::before { transform: translate(-50%,-50%); } .split-footer { grid-template-columns: 1fr; } }
        .cinema-footer { position: relative; z-index: 3; display: grid; grid-template-columns: 1.35fr 1fr; gap: 10px; padding: 0 18px 18px; }
        .cinema-caption { border-left: 2px solid var(--sm-amber); padding: 9px 11px; border-radius: 0 8px 8px 0; background: rgba(75,54,12,0.2); }
        .cinema-caption.secondary { border-left-color: var(--sm-cyan); background: rgba(10,35,43,0.3); }
        .cinema-caption-label { color: var(--sm-amber); font: 700 0.59rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
        .cinema-caption.secondary .cinema-caption-label { color: var(--sm-cyan); }
        .cinema-caption-text { color: #d7e7e7; font-size: 0.75rem; line-height: 1.4; margin-top: 5px; }
        .service-rail { display: flex; align-items: stretch; gap: 7px; margin-top: 12px; padding: 8px; border: 1px solid rgba(148,163,184,0.15); border-radius: 11px; background: rgba(8,19,25,0.68); }
        .service-rail-summary { display: flex; flex-direction: column; justify-content: center; min-width: 112px; padding: 4px 10px 4px 5px; border-right: 1px solid rgba(148,163,184,0.15); }
        .service-rail-kicker { color: var(--sm-muted); font: 700 0.58rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; text-transform: uppercase; }
        .service-rail-count { color: var(--sm-text); font-size: 0.86rem; font-weight: 740; margin-top: 6px; }
        .service-pill { flex: 1 1 0; min-width: 88px; padding: 8px 9px; border: 1px solid rgba(148,163,184,0.14); border-radius: 8px; background: rgba(2,8,23,0.42); }
        .service-pill-head { display: flex; align-items: center; gap: 6px; }
        .service-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--sm-muted); }
        .service-dot.online { background: var(--sm-mint); box-shadow: 0 0 10px rgba(94,234,212,0.55); }
        .service-dot.offline { background: var(--sm-coral); box-shadow: 0 0 10px rgba(251,113,133,0.42); }
        .service-name { color: #cbd5e1; font-size: 0.68rem; font-weight: 650; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .service-state { color: var(--sm-muted); font: 600 0.58rem/1 ui-monospace, SFMono-Regular, Menlo, monospace; margin-top: 6px; text-transform: uppercase; }
        @media (max-width: 900px) { .service-rail { flex-wrap: wrap; } .service-rail-summary { flex: 1 1 100%; border-right: 0; border-bottom: 1px solid rgba(148,163,184,0.15); padding: 4px 4px 9px; } .service-pill { min-width: 30%; } }
        @media (max-width: 900px) {
            .cinema-stage { min-height: 690px; }
            .cinema-canvas { height: 535px; }
            .cinema-node { width: 128px; }
            .cinema-node.origin { left: 2%; top: 9%; }
            .cinema-node.decoy { left: 52%; top: 9%; }
            .cinema-node.telemetry { left: 2%; top: 32%; }
            .cinema-node.bait { left: 52%; top: 32%; }
            .cinema-node.agent { left: 2%; top: 58%; }
            .cinema-node.detection { left: 52%; top: 58%; }
            .wire-1, .wire-2, .wire-3, .wire-4, .wire-5 { display: none; }
            .cinema-footer { grid-template-columns: 1fr; }
        }
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
    """Render the always-present cinematic narrative, driven by live telemetry."""
    sessions = _attack_sessions()
    latest = sessions[0] if sessions else None
    events = _session_events(latest.get("session_id")) if latest else []
    state = _story_state(latest, events)
    status_label = "Live" if state["running"] else ("Complete" if state["finished"] else "Ready")
    status_class = "" if state["running"] else "idle"
    active = state["active"]

    def node_state(start: int, end: int) -> str:
        if active < start:
            return "future"
        if start <= active <= end:
            return "current"
        return "complete"

    def wire_state(done_at: int) -> str:
        if active > done_at:
            return "done"
        if active == done_at:
            return "live"
        return ""

    node_markup = [
        ("origin", node_state(0, 0), "ATTACK ORIGIN", "Attacker", "A real simulator signal is moving toward the decoy."),
        ("decoy", node_state(1, 3), "DECOY SURFACE", "Fake SSH", "Cowrie absorbs the connection and login pressure."),
        ("telemetry", node_state(4, 4), "OBSERVABILITY", "Telemetry", "Events become a readable session story."),
        ("bait", node_state(5, 5), "DECEPTION LAYER", "AI bait", "A believable secret gives the attacker a reason to continue."),
        ("agent", node_state(6, 6), "ADAPTIVE LAYER", "Agent decision", "The system chooses how to keep the engagement alive."),
        ("detection", node_state(7, 7), "DEFENSIVE OUTPUT", "Rules", "Observed behaviour is turned into Snort and YARA evidence."),
    ]
    node_html = []
    for position, css_state, kind, name, copy in node_markup:
        node_html.append(
            f"<div class='cinema-node {position} {css_state}'>"
            f"<div class='cinema-node-type'>{_display(kind)}</div>"
            f"<div class='cinema-node-name'>{_display(name)}</div>"
            f"<div class='cinema-node-copy'>{_display(copy)}</div>"
            f"<span class='cinema-node-icon'></span></div>"
        )
    wires = "".join(
        f"<span class='cinema-wire wire-{number} {wire_state(done_at)}'></span>"
        for number, done_at in ((1, 1), (2, 4), (3, 5), (4, 6), (5, 7))
    )
    recent_event = events[-1] if events else {}
    event_label = explain_event_type(recent_event.get("event_type")) if recent_event else "No telemetry has reached the scene yet."
    command = latest.get("commands", [])[-1] if latest and latest.get("commands") else None
    observed_detail = explain_command(command) if command else state["observed"]
    progress = min(1.0, max(0.0, active / 7))
    attacker_steps = [active >= point for point in (1, 2, 4, 5)]
    response_steps = [active >= point for point in (4, 5, 6, 7)]
    attacker_event = event_label if latest else "Waiting for the first signal from the attacker simulator."
    response_event = state["current_detail"] if latest else "The adaptive layer is staged and ready to respond."
    attacker_progress = min(1.0, progress * 1.06)
    response_progress = min(1.0, max(0.0, (active - 3) / 4))
    split_html = f"""
        <section class="split-stage">
          <div class="split-head">
            <div><div class="split-head-title">The intrusion, in motion</div><div class="split-head-copy">Left side: what the attacker does. Right side: how ShadowMesh turns it into a longer, richer engagement.</div></div>
            <div class="split-state {status_class}"><span class="cinema-live-dot"></span>{status_label}</div>
          </div>
          <div class="split-body">
            <div class="split-pane left">
              <div class="split-pane-label">The attacker</div>
              <div class="split-pane-title">Pressure enters.</div>
              <div class="split-pane-copy">A repeatable profile probes the fake SSH service, tests credentials, and looks for anything worth stealing.</div>
              <div class="split-signal" style="--signal-progress:{attacker_progress:.3f}">
                <div class="split-event">{_display(attacker_event)} {_display(observed_detail)}</div>
                <div class="split-track"></div><div class="split-packet"></div>
              </div>
              <div class="split-steps">{''.join(f"<span class='split-step {'done' if done else ''}'></span>" for done in attacker_steps)}</div>
            </div>
            <div class="split-divider"></div>
            <div class="split-pane right">
              <div class="split-pane-label">ShadowMesh</div>
              <div class="split-pane-title">The decoy answers.</div>
              <div class="split-pane-copy">Telemetry, engineered bait, adaptive actions, and detection output turn the intrusion into intelligence.</div>
              <div class="split-signal" style="--signal-progress:{response_progress:.3f}">
                <div class="split-event">{_display(response_event)}</div>
                <div class="split-track"></div><div class="split-packet"></div>
              </div>
              <div class="split-steps">{''.join(f"<span class='split-step {'done' if done else ''}'></span>" for done in response_steps)}</div>
            </div>
          </div>
          <div class="split-footer">
            <div class="split-note"><strong>Current frame:</strong> {_display(state['current_detail'])}</div>
            <div class="split-note"><strong>Why it matters:</strong> {_display(state['observed'])}</div>
          </div>
        </section>
    """
    st.markdown(split_html, unsafe_allow_html=True)
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
            <div class="hero-kicker">ShadowMesh / Adaptive deception</div>
            <div class="hero-title">A breach that fights back.</div>
            <div class="hero-copy">Watch an intrusion cross the decoy boundary, discover engineered bait, trigger an adaptive response, and leave behind usable detection evidence.</div>
            <div class="hero-status"><span class="status-orb online"></span><strong>Live system ready</strong> · every movement is tied to real telemetry</div>
            <div class="signal-strip">
              <span class="signal-chip"><strong>SSH</strong> decoy</span>
              <span class="signal-chip"><strong>Live</strong> adaptation</span>
              <span class="signal-chip"><strong>AI</strong> deception</span>
              <span class="signal-chip"><strong>Snort + YARA</strong></span>
            </div>
          </div>
          <div class="mesh-mark" aria-label="ShadowMesh six-layer mesh emblem">
            <div class="mesh-ring"></div><div class="mesh-ring reverse"></div><div class="mesh-core">S/M</div>
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
    active = sum("running" in str(state).lower() for state in running.values()) if running else 0
    pills = []
    for label, state in service_states.items():
        online = state.lower() in {"online", "running"} or "running" in state.lower()
        pills.append(
            f"<div class='service-pill'><div class='service-pill-head'><span class='service-dot {'online' if online else 'offline'}'></span><span class='service-name'>{_display(label)}</span></div><div class='service-state'>{_display(state)}</div></div>"
        )
    cluster = health.get("status", "unknown") if ok else "unreachable"
    st.markdown(
        f"<div class='service-rail'><div class='service-rail-summary'><div class='service-rail-kicker'>System heartbeat</div><div class='service-rail-count'>{active}/6 services live</div></div>{''.join(pills)}</div>",
        unsafe_allow_html=True,
    )
    if not ok:
        st.caption("Elasticsearch is unreachable. Start the stack from the maintenance controls; the cinematic scene remains available in preview mode.")
    else:
        st.caption(f"Telemetry fabric: {cluster} cluster · the scene is fed by live service signals.")


def _service_state(running: dict[str, str], service: str) -> str:
    state = running.get(service) or running.get(f"infra-{service}-1")
    if not state:
        return "Not seen"
    return "Running" if "running" in state.lower() else state


def render_sidebar() -> str:
    """Provide a quiet review navigation rail without duplicating page content."""
    with st.sidebar:
        st.markdown("### ShadowMesh")
        st.caption("Live deception system")
        view = st.radio(
            "Workspace",
            ["Live Story", "Session Replay", "Decoy Library", "Detection Output"],
            label_visibility="collapsed",
        )
        st.divider()
        st.caption("One visual narrative over the independent ShadowMesh services.")
        st.markdown("#### Data sources")
        st.link_button("Open Kibana", "http://localhost:5601", width="stretch")
        st.link_button("Open Elasticsearch", ES_URL, width="stretch")
    return view


def render_controls() -> None:
    st.markdown('<div class="section-heading"><span class="section-index">01</span><div><div class="section-kicker">Simulation</div><div class="section-title">Run a live scenario</div></div></div>', unsafe_allow_html=True)
    st.caption("Choose an attacker behaviour. The split-screen sequence begins as soon as telemetry arrives.")
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
        if st.button("Start live attack", type="primary", width="stretch"):
            ok, output = _start_attack(profile, int(sessions))
            _remember_command(f"Run {profile} attack", ok, output)

    with st.expander("System tools"):
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
    st.markdown('<div class="section-heading"><span class="section-index">02</span><div><div class="section-kicker">Session replay</div><div class="section-title">What happened</div></div></div>', unsafe_allow_html=True)
    if not sessions:
        st.info("No session has reached Elasticsearch yet. Start a live attack from the story view.")
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
    st.markdown('<div class="section-heading"><span class="section-index">03</span><div><div class="section-kicker">Response</div><div class="section-title">How the decoy answered</div></div></div>', unsafe_allow_html=True)
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
    st.markdown('<div class="section-heading"><span class="section-index">03</span><div><div class="section-kicker">Detection evidence</div><div class="section-title">What the system produced</div></div></div>', unsafe_allow_html=True)
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
    st.markdown('<div class="section-heading"><span class="section-index">02</span><div><div class="section-kicker">Deception artifacts</div><div class="section-title">Inside the decoy</div></div></div>', unsafe_allow_html=True)
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
    st.markdown('<div class="section-heading"><span class="section-index">02</span><div><div class="section-kicker">Detection artifacts</div><div class="section-title">Generated rules</div></div></div>', unsafe_allow_html=True)
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

    if view == "Live Story":
        render_controls()
        render_live_story()
        render_status()
    elif view == "Session Replay":
        render_status()
        latest = render_live_overview(search_index("honeypot-sessions", size=12))
        render_story(latest)
        render_adaptive_actions()
    elif view == "Decoy Library":
        st.markdown('<div class="workspace-intro"><div class="section-kicker">Deception artifacts</div><div class="workspace-title">Decoy Library</div><div class="workspace-copy">Inspect the engineered files the attacker can discover inside the fake environment.</div></div>', unsafe_allow_html=True)
        render_bait_files()
    else:
        st.markdown('<div class="workspace-intro"><div class="section-kicker">Detection artifacts</div><div class="workspace-title">Detection Output</div><div class="workspace-copy">Review the defensive rules produced from the behaviour you just watched unfold.</div></div>', unsafe_allow_html=True)
        render_rule_files()
        render_generated_rule_records()

    st.caption(
        "Dashboard reads existing ShadowMesh services. It does not replace Cowrie, "
        "Elasticsearch, Kibana, the agent, or the rule generator."
    )


if __name__ == "__main__":
    main()
