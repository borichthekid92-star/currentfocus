#!/usr/bin/env python3
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, Response
import sqlite3
import subprocess
import time
import configparser
from functools import wraps
from datetime import datetime, timedelta
import json
import uuid
import threading
import logging
import operator
import re
import queue  # For SSE event queue
import os
from pathlib import Path
# Analytics dependencies
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False

try:
    from darts import TimeSeries
    from darts.models import ARIMA
    from darts.metrics import mae
    DARTS_AVAILABLE = True
except ImportError:
    DARTS_AVAILABLE = False


# ==================== ANALYTICS IMPORTS ====================

# -------------------------------------------------------
# GLOBAL LOCKS – MUST BE FIRST
# -------------------------------------------------------

rules_db_lock = threading.Lock()
analytics_db_lock = threading.Lock()
security_events_db_lock = threading.Lock()

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

# Session configuration
app.secret_key = config.get('session', 'secret_key', fallback='dev-secret-key-change-me')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(
    seconds=config.getint('session', 'session_timeout', fallback=3600)
)

# Database Paths
DB_PATH = "SecurityEvents.db"
ENDPOINTS_DB = "Endpoints.db"
ANALYTICS_DB = "analytics.db"
RULES_DB = r"C:\Users\brthekid\Desktop\Focus_Detection\Server_DB\rules.db"

# Alerts Directory
ALERTS_DIR = Path("Server_DB/alerts")

# Analytics settings (seconds)
ANALYTICS_INTERVAL = config.getint('analytics', 'interval_seconds', fallback=60)

latest_ipconfig_output = ""

# Login attempt tracking
login_attempts = {}

# ==================== CRITICAL: Endpoint Connection Tracking ====================
connected_endpoints = {}
pending_commands = {}
command_results = {}

# Lock for analytics DB writes (sqlite isn't fully threadsafe across connections in some cases)
analytics_db_lock = threading.Lock()

# Lock for SecurityEvents DB writes to transferred_events
security_events_db_lock = threading.Lock()

# SSE event queue for process events
process_event_queue = queue.Queue()

# ==================== DATA TRANSFER TRACKING ====================
# Track data transfer statistics
data_transfer_stats = {
    'total_events_received': 0,
    'last_transfer_time': None,
    'transfers_by_endpoint': {}
}
data_transfer_lock = threading.Lock()

# ==================== ANALYTICS GLOBALS ====================
active_analysis = None
analysis_results = {}
analysis_lock = threading.Lock()

# ==================== INITIALIZATION ====================

def init_security_events_db():
    """Initialize the main SecurityEvents database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            details TEXT
        )
    """)
    
    # New table for process events
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            pid INTEGER,
            ppid INTEGER,
            process_name TEXT,
            command_line TEXT,
            path TEXT,
            username TEXT
        )
    """)
    
    # Table to track transferred events from agents
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transferred_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id TEXT,
            agent_event_id INTEGER,
            timestamp TEXT,
            event_type TEXT,
            details TEXT,
            received_at TEXT
        )
    """)
    
    # Table to track triggered alerts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT,
            rule_name TEXT,
            severity TEXT,
            triggered_at TEXT,
            triggered_by TEXT,
            endpoint TEXT,
            event_details TEXT,
            event_ids TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    logger.info("[+] SecurityEvents.db initialized with process_events and transferred_events tables")

def init_endpoints_db():
    """Initialize endpoints database"""
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS endpoints (
            id TEXT PRIMARY KEY,
            hostname TEXT,
            ip_address TEXT,
            os_info TEXT,
            last_seen TEXT,
            status TEXT
        )
    """)
    
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS command_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command_id TEXT,
            endpoint_id TEXT,
            command TEXT,
            result TEXT,
            status TEXT,
            timestamp TEXT
        )
    """)
    
    conn.commit()
    conn.close()
    logger.info("[+] Endpoints.db initialized")

def init_analytics_db():
    """Initialize analytics database"""
    conn = sqlite3.connect(ANALYTICS_DB)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS process_analytics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            process_name TEXT,
            event_count INTEGER,
            category TEXT,
            rank INTEGER
        )
    """)

    # Optional: keep a short-lived summary table if needed in future
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS analytics_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            description TEXT
        )
    """)
    conn.commit()
    conn.close()
    logger.info("[+] analytics.db initialized")

def init_rules_db():
    conn = sqlite3.connect(RULES_DB, timeout=20)

    # IMPORTANT
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA busy_timeout=10000;")

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            name TEXT,
            keywords TEXT,
            severity TEXT,
            enabled INTEGER DEFAULT 1,
            description TEXT,
            rule_content TEXT,
            file_name TEXT UNIQUE,
            created_at TEXT,
            updated_at TEXT,
            last_synced TEXT
        )
    """)

    conn.commit()
    conn.close()


def ensure_rules_dir():
    """Create a rules.db SQLite database file in the current directory"""
    try:
        db_path = Path.cwd() / "rules.db"
        # Create the SQLite database file (this will create an empty DB if it doesn't exist)
        conn = sqlite3.connect(db_path)
        conn.close()
        logger.info(f"[+] Rules DB created: {db_path}")
        return db_path
    except Exception as e:
        logger.error(f"[-] Error creating rules DB: {e}")
        return None


# ==================== AUTHENTICATION ====================

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def check_login_attempts(username):
    """Check if user is locked out"""
    max_attempts = config.getint('security', 'max_login_attempts', fallback=5)
    lockout_duration = config.getint('security', 'lockout_duration', fallback=300)
    
    if username in login_attempts:
        attempts, last_attempt = login_attempts[username]
        
        if attempts >= max_attempts:
            time_passed = (datetime.now() - last_attempt).total_seconds()
            if time_passed < lockout_duration:
                remaining = int(lockout_duration - time_passed)
                return False, remaining
            else:
                login_attempts[username] = (0, datetime.now())
    
    return True, 0

def record_login_attempt(username, success):
    """Record login attempt"""
    if success:
        if username in login_attempts:
            del login_attempts[username]
    else:
        if username in login_attempts:
            attempts, _ = login_attempts[username]
            login_attempts[username] = (attempts + 1, datetime.now())
        else:
            login_attempts[username] = (1, datetime.now())

# ==================== DATABASE QUERIES ====================

def query_events(search="", event_type="", limit=100):
    """Query security events"""
    conn = None
    rows = []
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        query = "SELECT timestamp, event_type, details FROM transferred_events WHERE 1=1"
        params = []
        
        if search:
            query += " AND details LIKE ?"
            params.append(f"%{search}%")
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
    except sqlite3.OperationalError as e:
        logger.error(f"SQLite Error: {e}")
        rows = []
    finally:
        if conn:
            conn.close()
    return rows

def log_event(event_type, details):
    """Log an event to the database"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT INTO events (timestamp, event_type, details) VALUES (?, ?, ?)",
                   (timestamp, event_type, details))
    conn.commit()
    conn.close()

# ==================== DATA TRANSFER API ====================

@app.route("/api/data-transfer/receive", methods=["POST"])
def receive_data_transfer():
    """
    Receive data transfer from agent endpoints.
    Expects JSON with:
    {
        "endpoint_id": "xxx",
        "events": [
            {"id": 1, "timestamp": "...", "event_type": "...", "details": "..."},
            ...
        ]
    }
    """
    try:
        data = request.get_json() or {}
        endpoint_id = data.get('endpoint_id')
        events = data.get('events', [])
        
        logger.debug(f"[DEBUG] Received data-transfer request from {endpoint_id} with {len(events)} events")
        
        if not endpoint_id:
            logger.warning("[!] Data transfer request missing endpoint_id")
            return jsonify({'success': False, 'error': 'Missing endpoint_id'}), 400
        
        if not events or not isinstance(events, list):
            logger.warning(f"[!] Data transfer request from {endpoint_id} has invalid events: {events}")
            return jsonify({'success': False, 'error': 'Missing or invalid events array'}), 400
        
        # Insert events into the transferred_events table with locking
        with security_events_db_lock:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            received_at = datetime.now().isoformat()
            
            inserted_count = 0
            errors = []
            
            for event in events:
                try:
                    event_id = event.get('id')
                    timestamp = event.get('timestamp')
                    event_type = event.get('event_type')
                    details = event.get('details')
                    
                    logger.debug(f"[DEBUG] Inserting event: id={event_id}, type={event_type}, endpoint={endpoint_id}")
                    
                    cursor.execute("""
                        INSERT INTO transferred_events 
                        (endpoint_id, agent_event_id, timestamp, event_type, details, received_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        endpoint_id,
                        event_id,
                        timestamp,
                        event_type,
                        details,
                        received_at
                    ))
                    inserted_count += 1
                except Exception as e:
                    error_msg = f"Error inserting event {event.get('id')}: {str(e)}"
                    logger.error(f"[!] {error_msg}")
                    errors.append(error_msg)
                    continue
            
            conn.commit()
            conn.close()
            logger.info(f"[+] Committed {inserted_count} events from endpoint {endpoint_id} to transferred_events")
        
        # Update statistics
        with data_transfer_lock:
            data_transfer_stats['total_events_received'] += inserted_count
            data_transfer_stats['last_transfer_time'] = received_at
            
            if endpoint_id not in data_transfer_stats['transfers_by_endpoint']:
                data_transfer_stats['transfers_by_endpoint'][endpoint_id] = {
                    'total_events': 0,
                    'last_transfer': None
                }
            
            data_transfer_stats['transfers_by_endpoint'][endpoint_id]['total_events'] += inserted_count
            data_transfer_stats['transfers_by_endpoint'][endpoint_id]['last_transfer'] = received_at
        
        logger.info(f"[+] Successfully received {inserted_count} events from endpoint {endpoint_id}")
        
        response = {
            'success': True,
            'events_received': inserted_count,
            'message': f'Successfully received {inserted_count} events'
        }
        
        if errors:
            response['warnings'] = errors
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Data transfer error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/data-transfer/stats", methods=["GET"])
@login_required
def get_data_transfer_stats():
    """Get data transfer statistics"""
    with data_transfer_lock:
        return jsonify({
            'success': True,
            'stats': data_transfer_stats
        })

@app.route("/api/data-transfer/events", methods=["GET"])
@login_required
def get_transferred_events():
    """
    Query transferred events from agents.
    Query parameters:
    - endpoint_id: filter by endpoint (optional)
    - limit: number of events to return (default 100)
    """
    endpoint_id = request.args.get('endpoint_id')
    limit = int(request.args.get('limit', 100))
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        if endpoint_id:
            query = """
                SELECT id, endpoint_id, agent_event_id, timestamp, event_type, details, received_at
                FROM transferred_events
                WHERE endpoint_id = ?
                ORDER BY id DESC
                LIMIT ?
            """
            cursor.execute(query, (endpoint_id, limit))
        else:
            query = """
                SELECT id, endpoint_id, agent_event_id, timestamp, event_type, details, received_at
                FROM transferred_events
                ORDER BY id DESC
                LIMIT ?
            """
            cursor.execute(query, (limit,))
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            events.append({
                'id': row[0],
                'endpoint_id': row[1],
                'agent_event_id': row[2],
                'timestamp': row[3],
                'event_type': row[4],
                'details': row[5],
                'received_at': row[6]
            })
        
        return jsonify({
            'success': True,
            'events': events,
            'count': len(events)
        })
        
    except Exception as e:
        logger.error(f"Error querying transferred events: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
        
# ==================== ENDPOINT MANAGEMENT API ====================

@app.route("/api/endpoint/register", methods=["POST"])
def register_endpoint():
    """Register or update an endpoint"""
    data = request.get_json() or {}
    endpoint_id = data.get('endpoint_id')
    hostname = data.get('hostname')
    ip_address = data.get('ip_address')
    os_info = data.get('os_info')
    
    if not endpoint_id:
        return jsonify({'success': False, 'error': 'Missing endpoint_id'}), 400
    
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    
    cursor.execute("""
        INSERT OR REPLACE INTO endpoints (id, hostname, ip_address, os_info, last_seen, status)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (endpoint_id, hostname, ip_address, os_info, datetime.now().isoformat(), 'active'))
    
    conn.commit()
    conn.close()
    
    with data_transfer_lock:
        connected_endpoints[endpoint_id] = {
            'hostname': hostname,
            'ip': ip_address,
            'last_seen': datetime.now()
        }
    
    logger.info(f"[+] Endpoint registered: {endpoint_id} ({hostname})")
    log_event("ENDPOINT_REGISTERED", f"Endpoint {endpoint_id} ({hostname}) registered from {ip_address}")
    
    return jsonify({'success': True, 'message': 'Endpoint registered'})

@app.route("/api/endpoint/heartbeat", methods=["POST"])
def endpoint_heartbeat():
    """Update endpoint last seen timestamp"""
    data = request.get_json() or {}
    endpoint_id = data.get('endpoint_id')
    
    if not endpoint_id:
        return jsonify({'success': False, 'error': 'Missing endpoint_id'}), 400
    
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    cursor.execute("UPDATE endpoints SET last_seen = ?, status = ? WHERE id = ?",
                   (datetime.now().isoformat(), 'active', endpoint_id))
    conn.commit()
    conn.close()
    
    with data_transfer_lock:
        if endpoint_id in connected_endpoints:
            connected_endpoints[endpoint_id]['last_seen'] = datetime.now()
    
    return jsonify({'success': True})

@app.route("/api/endpoint/get-commands/<endpoint_id>", methods=["GET"])
def get_endpoint_commands(endpoint_id):
    """Get pending commands for an endpoint"""
    commands = []
    
    if endpoint_id in pending_commands:
        commands = pending_commands[endpoint_id]
        # Clear the commands after sending
        pending_commands[endpoint_id] = []
    
    return jsonify({'success': True, 'commands': commands})

@app.route("/api/endpoints/list", methods=["GET"])
@login_required
def list_endpoints():
    """List all registered endpoints"""
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT id, hostname, ip_address, os_info, last_seen, status FROM endpoints")
    rows = cursor.fetchall()
    conn.close()
    
    endpoints = []
    for row in rows:
        endpoints.append({
            'id': row[0],
            'hostname': row[1],
            'ip_address': row[2],
            'os_info': row[3],
            'last_seen': row[4],
            'status': row[5]
        })
    
    return jsonify({'success': True, 'endpoints': endpoints})

@app.route("/api/endpoint/send-command", methods=["POST"])
@login_required
def send_command_to_endpoint():
    """Queue a command for an endpoint"""
    username = session.get('username', 'unknown')
    data = request.get_json() or {}
    endpoint_id = data.get('endpoint_id')
    command = data.get('command')
    
    if not endpoint_id or not command:
        return jsonify({'success': False, 'error': 'Missing endpoint_id or command'}), 400
    
    command_id = str(uuid.uuid4())
    
    if endpoint_id not in pending_commands:
        pending_commands[endpoint_id] = []
    
    pending_commands[endpoint_id].append({
        'command_id': command_id,
        'command': command,
        'timestamp': datetime.now().isoformat()
    })
    
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO command_history (command_id, endpoint_id, command, result, status, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (command_id, endpoint_id, command, '', 'pending', datetime.now().isoformat()))
    conn.commit()
    conn.close()
    
    log_event("COMMAND_QUEUED", f"Command '{command}' queued by {username} for endpoint {endpoint_id}")
    logger.info(f"[+] Command {command_id} queued for {endpoint_id}: {command}")
    
    return jsonify({'success': True, 'command_id': command_id})
    


# ==================== PROCESS STATISTICS ====================

def get_process_stats():
    """Query DB and return process counts and ratios."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Example: assume table `process_events` with columns (id, timestamp, process_name)
    cur.execute("SELECT process_name, COUNT(*) FROM process_events GROUP BY process_name")
    rows = cur.fetchall()
    conn.close()

    if not rows:
        return []

    total = sum(count for _, count in rows)
    stats = []
    for proc, count in rows:
        ratio = round((count / total) * 100, 2)
        stats.append({"process": proc, "count": count, "ratio": ratio})
    return stats

@app.route("/api/risk-stats")
def risk_stats():
    stats = get_process_stats()

    # Bucket processes by ratio
    low_risk = [s for s in stats if s["ratio"] < 1]
    medium_risk = [s for s in stats if 1 <= s["ratio"] < 10]
    high_risk = [s for s in stats if 10 <= s["ratio"] < 30]

    return jsonify({
        "low_risk": sorted(low_risk, key=lambda x: x["ratio"])[:5],
        "medium_risk": sorted(medium_risk, key=lambda x: x["ratio"])[:5],
        "high_risk": sorted(high_risk, key=lambda x: x["ratio"])[:5]
    })

@app.route("/api/command-result/<command_id>", methods=["GET"])
@login_required
def get_command_result(command_id):
    """Get result of executed command"""
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT result, status FROM command_history WHERE command_id = ?
    """, (command_id,))
    row = cursor.fetchone()
    conn.close()
    
    if row:
        return jsonify({'success': True, 'result': row[0], 'status': row[1]})
    else:
        return jsonify({'success': False, 'error': 'Command not found'}), 404

@app.route("/api/endpoint/submit-result", methods=["POST"])
def submit_command_result():
    """Endpoint submits command result"""
    data = request.get_json() or {}
    command_id = data.get('command_id')
    result = data.get('result')
    status = data.get('status', 'completed')
    
    if not command_id:
        return jsonify({'success': False, 'error': 'Missing command_id'}), 400
    
    conn = sqlite3.connect(ENDPOINTS_DB)
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE command_history SET result = ?, status = ? WHERE command_id = ?
    """, (result, status, command_id))
    conn.commit()
    conn.close()
    
    logger.info(f"[+] Command result received for {command_id}: {status}")
    log_event("COMMAND_RESULT", f"Command {command_id} completed with status: {status}")
    
    return jsonify({'success': True})

# ==================== ANALYTICS API ====================

@app.route("/api/analytics/processes", methods=["GET"])
@login_required
def api_get_process_analytics():
    """
    Return most recent analytics rows (optionally filtered by top N and category).
    Example: /api/analytics/processes?limit=10&category=suspicious
    """
    limit = int(request.args.get('limit', 25))
    category = request.args.get('category', None)

    conn = sqlite3.connect(ANALYTICS_DB)
    cursor = conn.cursor()
    query = "SELECT timestamp, process_name, event_count, category, rank FROM process_analytics"
    params = []
    if category:
        query += " WHERE category = ?"
        params.append(category)
    query += " ORDER BY timestamp DESC, rank ASC LIMIT ?"
    params.append(limit)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()

    results = []
    for ts, pname, cnt, cat, rank in rows:
        results.append({
            'timestamp': ts,
            'process_name': pname,
            'event_count': cnt,
            'category': cat,
            'rank': rank
        })
    return jsonify({'success': True, 'analytics': results})

@app.route("/api/analytics/run", methods=["POST"])
@login_required
def api_run_analytics():
    """
    Trigger analytics run on-demand. Accept JSON body with optional window_minutes and top_n.
    """
    data = request.get_json() or {}
    window_minutes = int(data.get('window_minutes', config.getint('analytics', 'window_minutes', fallback=60)))
    top_n = int(data.get('top_n', config.getint('analytics', 'top_n', fallback=25)))

    # Note: analyze_processes function would need to be defined elsewhere
    # ok, items = analyze_processes(window_minutes=window_minutes, top_n=top_n)
    # if ok:
    #     return jsonify({'success': True, 'items': [{'process': p, 'count': c} for p, c in items]})
    # else:
    #     return jsonify({'success': False, 'error': 'Analytics failed'}), 500
    return jsonify({'success': True, 'message': 'Analytics endpoint placeholder'})

# ==================== ANALYTICS ROUTES (NEW) ====================

@app.route("/analytics")
@login_required
def analytics_page():
    """Analytics dashboard page"""
    return render_template('analytics.html')


@app.route("/api/analytics/start", methods=["POST"])
@login_required
def start_analytics():
    """
    Start a new analytics run
    
    POST data:
    {
        "zscore": 2.0
    }
    """
    global active_analysis, analysis_results
    
    try:
        data = request.get_json() or {}
        zscore = float(data.get('zscore', 2.0))
        
        # Validate zscore
        if zscore < 0:
            return jsonify({
                'success': False,
                'error': 'Z-score must be non-negative'
            }), 400
        
        with analysis_lock:
            # Check if analysis already running
            if active_analysis and active_analysis.is_running:
                return jsonify({
                    'success': False,
                    'error': 'Analysis already running',
                    'analysis_id': active_analysis.analysis_id
                }), 409
        
        # Create and start analytics
        analytics_engine = RuleAnalytics(
            zscore=zscore,
            rules_db=RULES_DB,
            events_db=DB_PATH,
            analytics_db=ANALYTICS_DB
        )
        
        with analysis_lock:
            active_analysis = analytics_engine
        
        # Run in background thread
        def run_background():
            global active_analysis, analysis_results
            logger.info(f"[ANALYTICS] Starting analysis with zscore={zscore}")
            
            result = analytics_engine.run_full_analysis()
            
            with analysis_lock:
                analysis_results[analytics_engine.analysis_id] = {
                    'zscore': zscore,
                    'status': 'completed' if result['success'] else 'failed',
                    'result': result,
                    'started_at': analytics_engine.start_time.isoformat() if analytics_engine.start_time else None,
                    'completed_at': datetime.now().isoformat()
                }
                active_analysis = None
        
        thread = threading.Thread(target=run_background, daemon=True)
        thread.start()
        
        log_event("ANALYTICS_STARTED", f"Analytics run started with zscore={zscore}")
        
        return jsonify({
            'success': True,
            'analysis_id': analytics_engine.analysis_id,
            'zscore': zscore,
            'message': 'Analytics analysis started. Phase 1: 20 mins (keywords), Phase 2: 40 mins (zscore). Total: ~60 minutes'
        })
    
    except ValueError as e:
        return jsonify({
            'success': False,
            'error': f'Invalid zscore value: {str(e)}'
        }), 400
    
    except Exception as e:
        logger.error(f"Error starting analytics: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route("/api/analytics/status", methods=["GET"])
@login_required
def analytics_status():
    """Get current analytics status"""
    global active_analysis
    
    try:
        status_data = {
            'is_running': False,
            'current_analysis': None,
            'recent_analyses': list(analysis_results.values())[-10:] if analysis_results else []
        }
        
        with analysis_lock:
            if active_analysis and active_analysis.is_running:
                elapsed = (datetime.now() - active_analysis.start_time).total_seconds() / 60 if active_analysis.start_time else 0
                
                status_data['is_running'] = True
                status_data['current_analysis'] = {
                    'analysis_id': active_analysis.analysis_id,
                    'zscore': active_analysis.zscore,
                    'elapsed_minutes': elapsed,
                    'phase1_results': active_analysis.phase1_results,
                    'phase2_results': active_analysis.phase2_results
                }
        
        return jsonify({
            'success': True,
            'data': status_data
        })
    
    except Exception as e:
        logger.error(f"Error getting analytics status: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route("/api/analytics/results/<analysis_id>", methods=["GET"])
@login_required
def analytics_results(analysis_id):
    """Get results for a specific analysis"""
    try:
        if analysis_id in analysis_results:
            return jsonify({
                'success': True,
                'results': analysis_results[analysis_id]
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Analysis not found'
            }), 404
    
    except Exception as e:
        logger.error(f"Error getting analytics results: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route("/api/analytics/stop", methods=["POST"])
@login_required
def stop_analytics():
    """Stop the current running analysis"""
    global active_analysis
    
    try:
        with analysis_lock:
            if active_analysis and active_analysis.is_running:
                active_analysis.is_running = False
                log_event("ANALYTICS_STOPPED", "User stopped analytics run")
                return jsonify({
                    'success': True,
                    'message': 'Analytics stopped',
                    'analysis_id': active_analysis.analysis_id
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'No analysis currently running'
                }), 400
    
    except Exception as e:
        logger.error(f"Error stopping analytics: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route("/api/analytics/history", methods=["GET"])
@login_required
def analytics_history():
    """Get all past analysis runs"""
    try:
        # Sort by most recent first
        history = sorted(
            analysis_results.values(),
            key=lambda x: x.get('completed_at', ''),
            reverse=True
        )
        
        return jsonify({
            'success': True,
            'total_runs': len(history),
            'runs': history[-50:] if len(history) > 50 else history  # Return last 50 runs
        })
    
    except Exception as e:
        logger.error(f"Error getting analytics history: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# ==================== Rules ====================


def convert_rule_name_to_filename(rule_name):
    """Convert rule name to safe filename"""
    # Remove special characters, convert spaces to underscores, lowercase
    safe_name = re.sub(r'[^a-zA-Z0-9_\-]', '', rule_name.replace(' ', '_').lower())
    return safe_name + '.json'


# ==================== RULE FILE STORAGE ENDPOINTS ====================
@app.route("/api/debug/db-check")
def debug_db_check():
    import os

    info = {
        "RULES_DB_PATH": RULES_DB,
        "FILE_EXISTS": os.path.exists(RULES_DB),
        "CWD": os.getcwd()
    }

    conn = sqlite3.connect(RULES_DB)
    cur = conn.cursor()

    cur.execute("select id,name,keywords from rules")
    rows = cur.fetchall()

    info["ROW_COUNT"] = len(rows)
    info["ROWS"] = rows

    conn.close()

    return jsonify(info)
    rule
import uuid
from datetime import datetime
import json
import sqlite3
import threading

rules_db_lock = threading.Lock()  # make sure this is at the top

@app.route("/api/rules/save", methods=["POST"])
def save_rule_to_db():
    """Create a rule in SQLite DB safely from a web app"""
    try:
        data = request.get_json()

        rule_name = data.get("ruleName")
        keyword = data.get("keyword")
        severity = data.get("severity", "MEDIUM").upper()
        description = data.get("description", "")

        if not rule_name or not keyword:
            return jsonify({"success": False, "error": "Rule name and keyword required"}), 400

        rule_id = str(uuid.uuid4())
        now = datetime.now().isoformat()

        # Build the rule object (can be stored as JSON)
        rule_object = {
            "id": rule_id,
            "name": rule_name,
            "keyword": keyword,
            "severity": severity,
            "description": description,
            "enabled": True,
            "created_at": now,
            "hit_count": 0,
            "last_triggered": None
        }

        # ───────────── CRITICAL SECTION ─────────────
        with rules_db_lock:
            conn = sqlite3.connect(RULES_DB, timeout=20)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA busy_timeout=10000;")  # 10 sec wait if DB locked
            cursor = conn.cursor()

            # Insert rule into DB
            cursor.execute("""
                INSERT INTO rules (
                    id,
                    name,
                    keywords,
                    severity,
                    description,
                    rule_content,
                    file_name,
                    created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                rule_id,
                rule_name,
                keyword,
                severity,
                description,
                json.dumps(rule_object),
                convert_rule_name_to_filename(rule_name),
                now
            ))

            conn.commit()
            conn.close()
        # ────────────────────────────────────────────

        return jsonify({"success": True, "rule_id": rule_id, "rule": rule_object})

    except sqlite3.OperationalError as e:
        # Handles "database is locked"
        return jsonify({"success": False, "error": "Database busy - try again in 1 second"}), 503

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/rules/list-files", methods=["GET"])
@login_required
def list_rule_files():
    """List all rule files in Server_DB/rules directory"""
    try:
        rules_dir = ensure_rules_dir()
        rules = []
        
        for json_file in rules_dir.glob('*.json'):
            try:
                with open(json_file, 'r') as f:
                    rule = json.load(f)
                    rules.append({
                        'filename': json_file.name,
                        'rule': rule
                    })
            except Exception as e:
                logger.warning(f"Error reading rule file {json_file}: {e}")
        
        return jsonify({
            'success': True,
            'rules': rules,
            'total': len(rules)
        })
    except Exception as e:
        logger.error(f"Error listing rule files: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== ALERT MANAGEMENT ENDPOINTS ====================

@app.route("/api/alerts/create", methods=["POST"])
def create_alert():
    """Record a triggered alert when a rule matches"""
    try:
        data = request.get_json()
        rule_id = data.get('rule_id')
        rule_name = data.get('rule_name')
        severity = data.get('severity', 'medium')
        endpoint = data.get('endpoint', 'unknown')
        event_details = data.get('event_details', '')
        event_ids = data.get('event_ids', [])  # List of matched event IDs
        
        if not rule_id or not rule_name:
            return jsonify({'success': False, 'error': 'Rule ID and name required'}), 400
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO alerts (
                rule_id, rule_name, severity, triggered_at, 
                triggered_by, endpoint, event_details, event_ids
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            rule_id,
            rule_name,
            severity,
            datetime.now().isoformat(),
            session.get('username', 'system'),
            endpoint,
            event_details,
            json.dumps(event_ids)
        ))
        
        conn.commit()
        alert_id = cursor.lastrowid
        conn.close()
        
        logger.info(f"[+] Alert created for rule: {rule_name} (Alert ID: {alert_id})")
        
        return jsonify({
            'success': True,
            'alert_id': alert_id
        })
    except Exception as e:
        logger.error(f"Error creating alert: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/alerts/all", methods=["GET"])
@login_required
def get_all_alerts():
    """Fetch all alerts with details, ordered by most recent"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        limit = request.args.get('limit', 100, type=int)
        
        cursor.execute("""
            SELECT id, rule_id, rule_name, severity, triggered_at, 
                   triggered_by, endpoint, event_details, event_ids
            FROM alerts
            ORDER BY triggered_at DESC
            LIMIT ?
        """, (limit,))
        
        rows = cursor.fetchall()
        alerts = []
        
        for row in rows:
            event_ids = json.loads(row['event_ids']) if row['event_ids'] else []
            alerts.append({
                'id': row['id'],
                'rule_id': row['rule_id'],
                'rule_name': row['rule_name'],
                'severity': row['severity'],
                'triggered_at': row['triggered_at'],
                'triggered_by': row['triggered_by'],
                'endpoint': row['endpoint'],
                'event_details': row['event_details'],
                'event_ids': event_ids
            })
        
        conn.close()
        
        return jsonify({
            'success': True,
            'alerts': alerts,
            'total': len(alerts)
        })
    except Exception as e:
        logger.error(f"Error fetching alerts: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route("/api/alerts/<int:alert_id>/events", methods=["GET"])
@login_required
def get_alert_events(alert_id):
    """Fetch event logs for a specific alert"""
    try:
        # Get alert details
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, rule_id, rule_name, severity, triggered_at, 
                   triggered_by, endpoint, event_details, event_ids
            FROM alerts
            WHERE id = ?
        """, (alert_id,))
        
        alert_row = cursor.fetchone()
        
        if not alert_row:
            conn.close()
            return jsonify({'success': False, 'error': 'Alert not found'}), 404
        
        event_ids = json.loads(alert_row['event_ids']) if alert_row['event_ids'] else []
        
        # Fetch events associated with this alert
        events = []
        if event_ids:
            placeholders = ','.join('?' * len(event_ids))
            cursor.execute(f"""
                SELECT id, timestamp, event_type, details
                FROM transferred_events
                WHERE id IN ({placeholders})
                ORDER BY timestamp DESC
            """, event_ids)
            
            event_rows = cursor.fetchall()
            events = [dict(row) for row in event_rows]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'alert': {
                'id': alert_row['id'],
                'rule_id': alert_row['rule_id'],
                'rule_name': alert_row['rule_name'],
                'severity': alert_row['severity'],
                'triggered_at': alert_row['triggered_at'],
                'triggered_by': alert_row['triggered_by'],
                'endpoint': alert_row['endpoint'],
                'event_details': alert_row['event_details']
            },
            'events': events
        })
    except Exception as e:
        logger.error(f"Error fetching alert events: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/api/rules/list", methods=["GET"])
def api_list_rules():
    """List all rules from Server_DB/rules.db"""
    try:
        # Connect to the database
        conn = sqlite3.connect(RULES_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Simple query: only select existing columns
        query = "SELECT id, name, keywords FROM rules ORDER BY name"
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()

        # Convert rows to dictionaries
        rules = [dict(row) for row in rows]

        print("[DEBUG] RULES RETURNED:", rules)  # debug output

        return jsonify({
            'success': True,
            'rules': rules,
            'total': len(rules)
        })

    except Exception as e:
        print(f"[ERROR] Listing rules failed: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500



@app.route("/api/rules/<rule_id>", methods=["GET"])
@login_required
def api_get_rule(rule_id):
    """Get a single rule by ID with full content"""
    try:
        conn = sqlite3.connect(RULES_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM rules WHERE id = ?
        """, (rule_id,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return jsonify({'success': False, 'error': 'Rule not found'}), 404
        
        rule_data = dict(row)
        
        # Parse rule_content back to JSON if it exists
        if rule_data['rule_content']:
            try:
                rule_data['rule_content_json'] = json.loads(rule_data['rule_content'])
            except:
                rule_data['rule_content_json'] = None
        
        return jsonify({
            'success': True,
            'rule': rule_data
        })
    
    except Exception as e:
        logger.error(f"Error getting rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route("/api/rules/by-file/<file_name>", methods=["GET"])
@login_required
def api_get_rule_by_file(file_name):
    """Get a single rule by file name with full content"""
    try:
        conn = sqlite3.connect(RULES_DB)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT * FROM rules WHERE file_name = ?
        """, (file_name,))
        
        row = cursor.fetchone()
        conn.close()
        
        if not row:
            return jsonify({'success': False, 'error': 'Rule not found'}), 404
        
        rule_data = dict(row)
        
        # Parse rule_content back to JSON if it exists
        if rule_data['rule_content']:
            try:
                rule_data['rule_content_json'] = json.loads(rule_data['rule_content'])
            except:
                rule_data['rule_content_json'] = None
        
        return jsonify({
            'success': True,
            'rule': rule_data
        })
    
    except Exception as e:
        logger.error(f"Error getting rule: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# ==================== LOGIN/LOGOUT ROUTES ====================

@app.route("/login", methods=["GET", "POST"])
def login():
    """Login page"""
    if request.method == "POST":
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check lockout
        allowed, remaining = check_login_attempts(username)
        if not allowed:
            flash(f'Too many failed attempts. Try again in {remaining} seconds.', 'danger')
            return render_template('login.html')
        
        # Simple authentication (replace with proper authentication)
        # Load credentials from config.ini
        config_username = config.get('authentication', 'username', fallback='admin')
        config_password = config.get('authentication', 'password', fallback='admin')
        
        if username == config_username and password == config_password:
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True
            record_login_attempt(username, True)
            log_event("USER_LOGIN", f"User {username} logged in successfully")
            return redirect(url_for('dashboard'))
        else:
            record_login_attempt(username, False)
            log_event("LOGIN_FAILED", f"Failed login attempt for user {username}")
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

@app.route("/logout")
def logout():
    """Logout"""
    username = session.get('username', 'unknown')
    session.clear()
    log_event("USER_LOGOUT", f"User {username} logged out")
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# ==================== MAIN ROUTES ====================

@app.route("/")
@login_required
def dashboard():
    """Dashboard page"""
    return render_template('dashboard.html')

@app.route("/events")
@login_required
def events():
    """Events page"""
    search = request.args.get('search', '')
    event_type = request.args.get('type', '')
    limit = int(request.args.get('limit', 100))
    
    rows = query_events(search, event_type, limit)
    
    return render_template('events.html', events=rows, search=search, event_type=event_type)

@app.route("/rules")
@login_required
def rules():
    """Rules authoring page"""
    return render_template('rules.html')

@app.route("/alerts")
@login_required
def alerts():
    """Alerts dashboard - shows only triggered rules"""
    return render_template('alerts.html')


# ==================== ERROR HANDLER ====================

@app.errorhandler(404)
def page_not_found(e):
    """404 handler"""
    return render_template('404.html'), 404


# === ADDED ROUTES FOR REMOTE EXEC PAGE ===

@app.route("/remote_exec")
@login_required
def remote_exec():
    """Render the remote command execution HTML page"""
    return render_template("remote_exec.html")
    

@app.route("/api/execute-command", methods=["POST"])
@login_required
def api_execute_command():
    """Alias route for frontend compatibility with /api/endpoint/send-command"""
    return send_command_to_endpoint()
    
# -----------------------------------------------------
# 5. Agent: Get queued commands
# -----------------------------------------------------

@app.route("/api/endpoint/get-commands/<endpoint_id>", methods=["GET"])
def get_commands(endpoint_id):
    cmds = pending_commands.get(endpoint_id, [])
    pending_commands[endpoint_id] = []  # clear after sending
    return jsonify({"success": True, "commands": cmds})

# -----------------------------------------------------
# 3. Web UI: Poll command result
# -----------------------------------------------------
@app.route("/api/command-result/<command_id>", methods=["GET"])
@login_required
def command_result(command_id):
    conn = sqlite3.connect(ENDPOINTS_DB)
    c = conn.cursor()
    c.execute("SELECT result, status FROM command_history WHERE command_id = ?", (command_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return jsonify({"success": True, "result": row[0], "status": row[1]})
    return jsonify({"success": False, "error": "Not found"}), 404
    
# -----------------------------------------------------
# 6. Agent: Submit command result
# -----------------------------------------------------
@app.route("/api/endpoint/submit-result", methods=["POST"])
def submit_result():
    data = request.get_json() or {}
    command_id = data.get("command_id")
    result = data.get("result")
    status = data.get("status", "completed")

    if not command_id:
        return jsonify({"success": False, "error": "Missing command_id"}), 400

    conn = sqlite3.connect(ENDPOINTS_DB)
    c = conn.cursor()
    c.execute("""
        UPDATE command_history
        SET result = ?, status = ?
        WHERE command_id = ?
    """, (result, status, command_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True})
    


# ==================== ANALYTICS INTEGRATION ====================
# Anomaly Detection using ARIMA forecasting
# Runs as background thread within Flask service
# ================================================================

def create_anom_table():
    """Create anom_vars table in analytics.db if not exists"""
    try:
        conn = sqlite3.connect(ANALYTICS_DB)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS anom_vars (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                var10min INTEGER,
                var20min INTEGER,
                var30min INTEGER,
                anomaly_score REAL,
                is_anomaly INTEGER
            )
        """)
        conn.commit()
        conn.close()
        logger.info("[+] Analytics anom_vars table ready")
    except Exception as e:
        logger.error(f"[-] Error creating anom_vars table: {e}")

def analytics_load_one_rule_keywords():
    """Load keywords from first active rule in rules.db"""
    try:
        with rules_db_lock:
            conn = sqlite3.connect(RULES_DB)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT keywords FROM rules WHERE enabled=1 LIMIT 1")
            row = cursor.fetchone()
            conn.close()
            if row:
                return analytics_parse_keywords(row['keywords'])
        return []
    except Exception as e:
        logger.warning(f"[!] Error loading rule keywords for analytics: {e}")
        return []

def analytics_parse_keywords(keywords_str):
    """Parse keywords from comma-separated string or JSON array"""
    if not keywords_str:
        return []
    try:
        if keywords_str.startswith("["):
            return json.loads(keywords_str)
        return [kw.strip() for kw in keywords_str.split(",") if kw.strip()]
    except Exception as e:
        logger.warning(f"[!] Error parsing keywords: {e}")
        return [keywords_str.strip()] if keywords_str else []

def analytics_count_matches(start_time, end_time, keywords):
    """Count events matching keywords between start_time and end_time"""
    if not keywords:
        return 0
    
    try:
        with security_events_db_lock:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            start_iso = start_time.isoformat()
            end_iso = end_time.isoformat()
            
            cursor.execute("PRAGMA table_info(transferred_events)")
            columns = [col[1] for col in cursor.fetchall()]
            
            if not columns:
                logger.warning("[!] No columns in transferred_events table")
                conn.close()
                return 0
            
            conditions = []
            params = []
            for kw in keywords:
                for col in columns:
                    conditions.append(f"{col} LIKE ?")
                    params.append(f"%{kw}%")
            
            total_hits = 0
            if conditions:
                sql = f"SELECT COUNT(*) FROM transferred_events WHERE timestamp BETWEEN ? AND ? AND ({' OR '.join(conditions)})"
                cursor.execute(sql, [start_iso, end_iso, *params])
                total_hits = cursor.fetchone()[0]
            
            conn.close()
            return total_hits
    except Exception as e:
        logger.error(f"[-] Error counting matches in analytics: {e}")
        return 0

def analytics_load_historical_data():
    """Load historical anom_vars data as pandas DataFrame"""
    if not PANDAS_AVAILABLE:
        return None
    
    try:
        with analytics_db_lock:
            conn = sqlite3.connect(ANALYTICS_DB)
            df = pd.read_sql_query(
                "SELECT timestamp, var10min, var20min, var30min FROM anom_vars ORDER BY timestamp",
                conn
            )
            conn.close()
            
            if df.empty:
                return None
            
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df.set_index('timestamp', inplace=True)
            return df
    except Exception as e:
        logger.warning(f"[!] Error loading historical analytics data: {e}")
        return None

def analytics_detect_anomalies(ts, new_value):
    """Use Darts ARIMA to detect anomaly"""
    if not DARTS_AVAILABLE:
        return 0.0, 0
    
    try:
        if len(ts) < 5:
            return 0.0, 0
        
        model = ARIMA(p=1, d=1, q=1)
        model.fit(ts)
        
        forecast = model.predict(n=1)
        actual_ts = TimeSeries.from_values([new_value])
        anomaly_score = mae(forecast, actual_ts)
        
        mean_score = ts.values().mean() if len(ts) > 0 else 0
        std_score = ts.values().std() if len(ts) > 1 else 1
        threshold = mean_score + 2 * std_score
        is_anomaly = 1 if anomaly_score > threshold else 0
        
        return float(anomaly_score), int(is_anomaly)
    except Exception as e:
        logger.warning(f"[!] Error in anomaly detection: {e}")
        return 0.0, 0

analytics_shutdown_event = threading.Event()

def analytics_wait_interruptible(seconds):
    """Sleep but check shutdown flag every second"""
    end_time = time.time() + seconds
    while time.time() < end_time:
        if analytics_shutdown_event.is_set():
            return False
        time.sleep(1)
    return True

def analytics_monitor():
    """Background thread: continuous anomaly detection"""
    logger.info("[*] Analytics monitor thread started")
    
    if not PANDAS_AVAILABLE:
        logger.warning("[!] Pandas not available - analytics disabled")
        return
    
    cycle_count = 0
    ANALYTICS_CYCLE_INTERVAL = 10
    
    try:
        while not analytics_shutdown_event.is_set():
            cycle_count += 1
            logger.info(f"[ANALYTICS CYCLE #{cycle_count}] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            
            keywords = analytics_load_one_rule_keywords()
            if not keywords:
                logger.debug("[ANALYTICS] No active rules, skipping cycle")
                if not analytics_wait_interruptible(60):
                    break
                continue
            
            try:
                now = datetime.now()
                end_time = now
                start_time = end_time - timedelta(minutes=10)
                count_10 = analytics_count_matches(start_time, end_time, keywords)
                logger.debug(f"[ANALYTICS] 10min: {count_10} matches")
                
                anomaly_score_10, is_anomaly_10 = 0.0, 0
                if DARTS_AVAILABLE and PANDAS_AVAILABLE:
                    hist_df = analytics_load_historical_data()
                    if hist_df is not None and 'var10min' in hist_df.columns:
                        ts_10 = TimeSeries.from_dataframe(hist_df, value_cols=['var10min'])
                        anomaly_score_10, is_anomaly_10 = analytics_detect_anomalies(ts_10, count_10)
                
                if not analytics_wait_interruptible(ANALYTICS_CYCLE_INTERVAL * 60):
                    break
                
                end_time = datetime.now()
                start_time = end_time - timedelta(minutes=20)
                count_20 = analytics_count_matches(start_time, end_time, keywords)
                logger.debug(f"[ANALYTICS] 20min: {count_20} matches")
                
                anomaly_score_20, is_anomaly_20 = 0.0, 0
                if DARTS_AVAILABLE and PANDAS_AVAILABLE:
                    hist_df = analytics_load_historical_data()
                    if hist_df is not None and 'var20min' in hist_df.columns:
                        ts_20 = TimeSeries.from_dataframe(hist_df, value_cols=['var20min'])
                        anomaly_score_20, is_anomaly_20 = analytics_detect_anomalies(ts_20, count_20)
                
                if not analytics_wait_interruptible(ANALYTICS_CYCLE_INTERVAL * 60):
                    break
                
                end_time = datetime.now()
                start_time = end_time - timedelta(minutes=30)
                count_30 = analytics_count_matches(start_time, end_time, keywords)
                logger.debug(f"[ANALYTICS] 30min: {count_30} matches")
                
                anomaly_score_30, is_anomaly_30 = 0.0, 0
                if DARTS_AVAILABLE and PANDAS_AVAILABLE:
                    hist_df = analytics_load_historical_data()
                    if hist_df is not None and 'var30min' in hist_df.columns:
                        ts_30 = TimeSeries.from_dataframe(hist_df, value_cols=['var30min'])
                        anomaly_score_30, is_anomaly_30 = analytics_detect_anomalies(ts_30, count_30)
                
                overall_anomaly_score = anomaly_score_30
                overall_is_anomaly = is_anomaly_30
                
                with analytics_db_lock:
                    conn = sqlite3.connect(ANALYTICS_DB)
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO anom_vars (
                            timestamp, var10min, var20min, var30min, anomaly_score, is_anomaly
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        datetime.now().isoformat(),
                        count_10,
                        count_20,
                        count_30,
                        overall_anomaly_score,
                        overall_is_anomaly
                    ))
                    conn.commit()
                    conn.close()
                
                alert_status = "ANOMALY!" if overall_is_anomaly else "NORMAL"
                logger.info(f"[ANALYTICS] Cycle #{cycle_count}: 10m={count_10}, 20m={count_20}, 30m={count_30}, score={overall_anomaly_score:.2f} [{alert_status}]")
                
                if not analytics_wait_interruptible(60):
                    break
                    
            except Exception as e:
                logger.error(f"[-] Error in analytics cycle: {e}")
                if not analytics_wait_interruptible(30):
                    break
    
    except Exception as e:
        logger.error(f"[-] Analytics monitor fatal error: {e}")
    finally:
        logger.info(f"[*] Analytics monitor stopped after {cycle_count} cycles")


if __name__ == "__main__":
    logger.info("[*] Initializing directories...")
    ensure_rules_dir()
    
    logger.info("[*] Initializing databases...")
    init_security_events_db()
    init_endpoints_db()
    init_analytics_db()
    init_rules_db()

    logger.info("[+] Configuration loaded")
    logger.info(f"[+] Starting Flask server on http://0.0.0.0:5000")
    logger.info("[+] Data transfer endpoint active at /api/data-transfer/receive")
    logger.info("[+] Connected endpoints: Use /api/endpoints/list to view")
    logger.info("[+] Analytics available at /analytics")
    logger.info("[+] Rules synced from /rules directory automatically every 15 minutes")
    # Start analytics monitoring thread
    logger.info("[+] Starting analytics monitor thread...")
    create_anom_table()
    analytics_thread = threading.Thread(target=analytics_monitor, daemon=False)
    analytics_thread.start()
    
    try:
        logger.info("[+] Flask server ready. Press Ctrl+C to stop.")
        app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
    except KeyboardInterrupt:
        logger.info("[*] Received shutdown signal")
    finally:
        logger.info("[*] Shutting down analytics monitor...")
        analytics_shutdown_event.set()
        analytics_thread.join(timeout=30)
        logger.info("[+] Analytics monitor stopped")
        logger.info("[+] Shutdown complete")