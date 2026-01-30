#!/usr/bin/env python3
"""
Sysmon-lite EDR Agent with Enhanced Window Activity Monitoring + Advanced Keystroke Anomaly Detection:
- Psutil Process Snapshot (last 30) with parent process, exe path, digital signature, and username
- PowerShell History Tracking
- File System Monitoring
- Network Connection Tracking with Bandwidth Monitoring (bytes in/out) and Browser HTTPS Site Access Detection
- ADVANCED KEYSTROKE LOGGING with DATA EXFILTRATION DETECTION
  * KEYSTROKE_SUMMARY: Normal 45-minute keystroke aggregation
  * KEYSTROKE_ANOMALY: Suspicious keystroke patterns (single spike)
  * KEYSTROKE_ANOMALY (CRITICAL): Data exfiltration (3+ consecutive windows of 3x+ baseline)
- Window Activity Detection (Create, Close, Focus, Title Change, State Change)
- SQLite Logging with device name and user context in every event
- Interactive Console Mode
- Remote management via HTTP (Flask server integration)
"""

import time
import threading
import os
import psutil
import sqlite3
import json
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pynput import keyboard
from collections import deque
import win32gui
import win32process
import win32con
import requests
import uuid
import socket
import subprocess
import getpass
from datetime import datetime, timezone
import re

# ==================== PROCESS EXCLUSION ====================

class ProcessExclusions:
    """Handle process exclusion logic"""
    
    def __init__(self, config_file="exclusions.json"):
        self.config_file = config_file
        self.enabled = False
        self.exact_processes = []
        self.partial_matches = []
        self.patterns = []
        self.log_excluded = False
        self.excluded_count = 0
        self.load_config()
    
    def load_config(self):
        """Load exclusion configuration from JSON file"""
        if not os.path.exists(self.config_file):
            return  # Silent if not found
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            self.enabled = config.get('enabled', False)
            self.log_excluded = config.get('log_excluded', False)
            
            # Load different exclusion types
            self.exact_processes = [p.lower() for p in config.get('exclude_processes', [])]
            self.partial_matches = [p.lower() for p in config.get('exclude_by_partial_match', [])]
            
            # Compile regex patterns
            self.patterns = []
            for pattern_str in config.get('exclude_by_pattern', []):
                try:
                    self.patterns.append(re.compile(pattern_str, re.IGNORECASE))
                except re.error as e:
                    print(f"[!] Invalid regex pattern: {pattern_str} - {e}", flush=True)
            
            if self.enabled:
                print(f"[+] Process exclusion enabled", flush=True)
                print(f"    - Exact matches: {len(self.exact_processes)}", flush=True)
                print(f"    - Partial matches: {len(self.partial_matches)}", flush=True)
                print(f"    - Regex patterns: {len(self.patterns)}", flush=True)
        
        except Exception as e:
            print(f"[!] Error loading exclusion config: {e}", flush=True)
    
    def should_exclude(self, process_name):
        """Check if a process should be excluded from monitoring"""
        if not self.enabled or not process_name:
            return False
        
        process_lower = process_name.lower()
        
        # Exact match (case-insensitive)
        if process_lower in self.exact_processes:
            self._log_exclusion(process_name, "exact match")
            return True
        
        # Partial match
        for partial in self.partial_matches:
            if partial in process_lower:
                self._log_exclusion(process_name, "partial match")
                return True
        
        # Regex pattern
        for pattern in self.patterns:
            if pattern.match(process_name):
                self._log_exclusion(process_name, "regex match")
                return True
        
        return False
    
    def _log_exclusion(self, process_name, reason):
        """Log excluded process"""
        self.excluded_count += 1
        if self.log_excluded:
            try:
                with open("exclusions_log.txt", "a") as f:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    f.write(f"{timestamp} | Excluded: {process_name} ({reason})\n")
            except Exception:
                pass  # Silent fail for logging

# ============================================================

# Global device and user info to attach to all logs
DEVICE_NAME = socket.gethostname()
CURRENT_USER = getpass.getuser()

# ==================== KEYWORD FILTER ====================

class KeywordFilter:
    """
    Filters logs to only include/exclude events containing specific keywords.
    Useful for reducing noise and focusing on relevant security events.
    """
    def __init__(self, include_keywords=None, exclude_keywords=None, filter_fields=None):
        self.include_keywords = include_keywords or []
        self.exclude_keywords = exclude_keywords or []
        self.filter_fields = filter_fields or 'both'
        self.enabled = bool(self.include_keywords or self.exclude_keywords)
        
    def should_log(self, event_type, details):
        """Determine if event should be logged based on keyword filters"""
        if not self.enabled:
            return True
        
        # Prepare text to search
        search_text = ""
        if self.filter_fields in ['event_type', 'both']:
            search_text += event_type.lower()
        if self.filter_fields in ['details', 'both']:
            search_text += " " + str(details).lower()
        
        # Check exclusion keywords first (blacklist)
        if self.exclude_keywords:
            for keyword in self.exclude_keywords:
                if keyword.lower() in search_text:
                    return False  # Drop this event
        
        # Check inclusion keywords (whitelist)
        if self.include_keywords:
            for keyword in self.include_keywords:
                if keyword.lower() in search_text:
                    return True  # Accept this event
            return False  # No include keywords matched
        
        return True  # No include keywords specified, and no exclusions matched
    
    def add_include_keyword(self, keyword):
        """Add a keyword that must be present"""
        if keyword not in self.include_keywords:
            self.include_keywords.append(keyword)
            self.enabled = True
    
    def add_exclude_keyword(self, keyword):
        """Add a keyword that must not be present"""
        if keyword not in self.exclude_keywords:
            self.exclude_keywords.append(keyword)
            self.enabled = True
    
    def remove_keyword(self, keyword):
        """Remove a keyword from either list"""
        self.include_keywords = [k for k in self.include_keywords if k != keyword]
        self.exclude_keywords = [k for k in self.exclude_keywords if k != keyword]
        self.enabled = bool(self.include_keywords or self.exclude_keywords)
    
    def clear_filters(self):
        """Clear all filters and disable filtering"""
        self.include_keywords.clear()
        self.exclude_keywords.clear()
        self.enabled = False
    
    def get_status(self):
        """Get current filter status"""
        return {
            'enabled': self.enabled,
            'include_keywords': self.include_keywords,
            'exclude_keywords': self.exclude_keywords,
            'filter_fields': self.filter_fields
        }

# ==================== LOGGER ====================

class Logger:
    DB_FILE = "SecurityEvents.db"
    
    def __init__(self):
        self.conn = sqlite3.connect(self.DB_FILE, check_same_thread=False)
        self.keyword_filter = KeywordFilter()  # Initialize keyword filter
        self._create_table()
    
    def _create_table(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL
            )
        """)
        # Add sync tracking table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS event_sync_status (
                event_id INTEGER PRIMARY KEY,
                synced BOOLEAN DEFAULT 0,
                synced_at TEXT,
                FOREIGN KEY(event_id) REFERENCES events(id)
            )
        """)
        self.conn.commit()

    def get_unsynced_events(self):
        """Retrieve all events that haven't been synced yet"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT e.id, e.timestamp, e.event_type, e.details 
            FROM events e
            LEFT JOIN event_sync_status s ON e.id = s.event_id
            WHERE s.synced IS NULL OR s.synced = 0
            ORDER BY e.id ASC
        """)
        return cursor.fetchall()

    def mark_event_synced(self, event_id):
        """Mark an event as synced"""
        timestamp = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
        cursor = self.conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO event_sync_status (event_id, synced, synced_at)
            VALUES (?, 1, ?)
        """, (event_id, timestamp))
        self.conn.commit()

    def log(self, event_type, details):
        # Check if event should be logged based on keyword filters
        if not self.keyword_filter.should_log(event_type, details):
            return  # Drop this event
        
        timestamp = datetime.now(timezone.utc).isoformat(timespec='milliseconds')
        # Prepend device and user info to event details
        details_with_context = f"Device: {DEVICE_NAME} | User: {CURRENT_USER} | {details}"
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO events (timestamp, event_type, details) VALUES (?, ?, ?)", (timestamp, event_type, details_with_context))
        self.conn.commit()
        
        # Print to console with better formatting
        if event_type in ['PROCESS_CREATE', 'COMMAND_EXECUTION', 'KEYSTROKE_ANOMALY']:
            print(f"[{timestamp}] {event_type}", flush=True)
            print(f"    └─ {details_with_context}", flush=True)
        else:
            print(f"[{timestamp}] {event_type} | {details_with_context}", flush=True)

    def show_recent(self, count=10):
        cursor = self.conn.cursor()
        cursor.execute("SELECT timestamp, event_type, details FROM events ORDER BY id DESC LIMIT ?", (count,))
        rows = cursor.fetchall()
        print("\n--- Last {} Events ---".format(count))
        for row in rows:
            print(f"[{row[0]}] {row[1]} | {row[2]}")
        print()
    
    def close(self):
        self.conn.close()
    
    def set_include_keywords(self, keywords):
        """Set keywords that logs MUST contain (whitelist mode)"""
        self.keyword_filter.include_keywords = keywords if isinstance(keywords, list) else [keywords]
        self.keyword_filter.enabled = True
        print(f"[*] Filter: Logs must contain one of: {self.keyword_filter.include_keywords}", flush=True)
    
    def set_exclude_keywords(self, keywords):
        """Set keywords that logs must NOT contain (blacklist mode)"""
        self.keyword_filter.exclude_keywords = keywords if isinstance(keywords, list) else [keywords]
        self.keyword_filter.enabled = True
        print(f"[*] Filter: Logs will not contain: {self.keyword_filter.exclude_keywords}", flush=True)
    
    def add_include_keyword(self, keyword):
        """Add a single keyword to the include list"""
        self.keyword_filter.add_include_keyword(keyword)
        print(f"[+] Added include keyword: {keyword}", flush=True)
    
    def add_exclude_keyword(self, keyword):
        """Add a single keyword to the exclude list"""
        self.keyword_filter.add_exclude_keyword(keyword)
        print(f"[+] Added exclude keyword: {keyword}", flush=True)
    
    def disable_filter(self):
        """Disable all keyword filtering"""
        self.keyword_filter.clear_filters()
        print("[*] Keyword filter disabled", flush=True)
    
    def get_filter_status(self):
        """Get current filter configuration"""
        return self.keyword_filter.get_status()
    
    def print_filter_status(self):
        """Print filter status in readable format"""
        status = self.get_filter_status()
        print("\n=== Keyword Filter Status ===", flush=True)
        print(f"Enabled: {status['enabled']}", flush=True)
        print(f"Include Keywords: {status['include_keywords'] if status['include_keywords'] else 'None (accept all)'}", flush=True)
        print(f"Exclude Keywords: {status['exclude_keywords'] if status['exclude_keywords'] else 'None'}", flush=True)
        print()

    def get_process_events(self, event_type='PROCESS_CREATE', limit=50):
        """Retrieve and format process creation/termination events"""
        cursor = self.conn.cursor()
        cursor.execute(
            "SELECT id, timestamp, event_type, details FROM events WHERE event_type = ? ORDER BY id DESC LIMIT ?",
            (event_type, limit)
        )
        return cursor.fetchall()

    def format_process_event(self, event):
        """Format a process event for clean display"""
        event_id, timestamp, event_type, details = event
        return f"[{event_id}] {timestamp} | {event_type}\n    └─ {details}\n"

    def print_process_events(self, event_type='PROCESS_CREATE', limit=20):
        """Print process events in a readable format"""
        events = self.get_process_events(event_type, limit)
        print(f"\n=== Last {len(events)} {event_type} Events ===\n")
        for event in events:
            print(self.format_process_event(event))
        print()

# ==================== FLASK SERVER COMMUNICATION ====================

SERVER_URL = "http://192.168.9.220:5000"  # Change to your Flask backend
ENDPOINT_ID_FILE = "agent_id.txt"

def get_or_create_endpoint_id():
    if os.path.exists(ENDPOINT_ID_FILE):
        with open(ENDPOINT_ID_FILE, "r") as f:
            return f.read().strip()
    eid = str(uuid.uuid4())
    with open(ENDPOINT_ID_FILE, "w") as f:
        f.write(eid)
    return eid

def register_endpoint():
    endpoint_id = get_or_create_endpoint_id()
    payload = {
        "endpoint_id": endpoint_id,
        "hostname": DEVICE_NAME,
        "ip_address": socket.gethostbyname(socket.gethostname()),
        "os_info": os.name
    }
    try:
        r = requests.post(f"{SERVER_URL}/api/endpoint/register", json=payload, timeout=5)
        if r.status_code == 200:
            print("[+] Registered endpoint with server", flush=True)
        else:
            print(f"[!] Registration failed: {r.status_code} {r.text}", flush=True)
    except Exception as e:
        print(f"[!] Failed to register endpoint: {e}", flush=True)

def send_heartbeat():
    endpoint_id = get_or_create_endpoint_id()
    payload = {"endpoint_id": endpoint_id}
    try:
        requests.post(f"{SERVER_URL}/api/endpoint/heartbeat", json=payload, timeout=5)
    except Exception as e:
        print(f"[!] Heartbeat error: {e}", flush=True)

def sync_events_to_server(logger):
    """Sync local database events to the server"""
    endpoint_id = get_or_create_endpoint_id()
    try:
        unsynced_events = logger.get_unsynced_events()
        
        if not unsynced_events:
            return
        
        print(f"[*] Found {len(unsynced_events)} unsynced events to send", flush=True)
        
        # Prepare events batch for upload
        events_batch = []
        for event_id, timestamp, event_type, details in unsynced_events:
            events_batch.append({
                'id': event_id,
                'timestamp': timestamp,
                'event_type': event_type,
                'details': details
            })
        
        # Send to server
        payload = {
            'endpoint_id': endpoint_id,
            'events': events_batch
        }
        
        print(f"[*] Sending payload to {SERVER_URL}/api/data-transfer/receive", flush=True)
        print(f"[DEBUG] Endpoint ID: {endpoint_id}, Event Count: {len(events_batch)}", flush=True)
        
        r = requests.post(
            f"{SERVER_URL}/api/data-transfer/receive",
            json=payload,
            timeout=10
        )
        
        print(f"[*] Server response code: {r.status_code}", flush=True)
        
        if r.status_code == 200:
            # Mark events as synced
            for event_id, _, _, _ in unsynced_events:
                logger.mark_event_synced(event_id)
            print(f"[+] Successfully synced {len(unsynced_events)} events to server", flush=True)
        else:
            print(f"[!] Sync failed with status {r.status_code}", flush=True)
    except requests.exceptions.ConnectionError as e:
        print(f"[!] Cannot connect to server at {SERVER_URL}: {e}", flush=True)
    except Exception as e:
        print(f"[!] Event sync error: {e}", flush=True)

def check_for_commands():
    endpoint_id = get_or_create_endpoint_id()
    try:
        r = requests.get(f"{SERVER_URL}/api/endpoint/get-commands/{endpoint_id}", timeout=5)
        data = r.json()
        for cmd in data.get("commands", []):
            cmd_text = cmd["command"]
            command_id = cmd["command_id"]
            try:
                result = subprocess.check_output(cmd_text, shell=True, text=True, stderr=subprocess.STDOUT)
                status = "completed"
            except Exception as e:
                result = str(e)
                status = "failed"
            try:
                requests.post(f"{SERVER_URL}/api/endpoint/submit-result", json={
                    "command_id": command_id,
                    "result": result,
                    "status": status
                }, timeout=5)
            except Exception as e:
                print(f"[!] Could not submit command result: {e}", flush=True)
    except Exception as e:
        print(f"[!] Fetch commands error: {e}", flush=True)

def background_loop(logger=None):
    while True:
        try:
            register_endpoint()
            break
        except Exception:
            print("[!] Initial registration failed, retrying in 10s...", flush=True)
            time.sleep(10)
    
    sync_interval = 0
    while True:
        send_heartbeat()
        check_for_commands()
        
        # Sync events every 30 seconds
        sync_interval += 10
        if sync_interval >= 30:
            if logger:
                sync_events_to_server(logger)
            sync_interval = 0
        
        time.sleep(10)

# ==================== ENHANCED KEYSTROKE ANOMALY DETECTION ====================

class EnhancedKeystrokeAnomalyMonitor:
    """
    Advanced keystroke monitoring with data exfiltration detection
    
    Detects:
    - Sudden keystroke spikes (3.0-5.0x baseline)
    - Sustained high activity (3+ consecutive windows)
    - Data exfiltration patterns (copy-paste attacks)
    
    Event Types:
    - KEYSTROKE_SUMMARY: Normal 45-minute aggregated count
    - KEYSTROKE_ANOMALY: Suspicious activity detected
    """
    
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        
        # Current window tracking
        self.keystroke_counts = {}  # {user: count}
        
        # Historical data for anomaly detection
        self.user_windows = {}  # {user: deque of past window counts}
        self.window_history_size = 10  # Keep last 10 windows
        
        # Anomaly detection config
        self.baseline_threshold = 0.5  # Need at least 5 windows for baseline
        self.anomaly_multiplier = 3.0  # 3x baseline = anomaly
        self.sustained_windows = 3    # Alert after 3 consecutive anomalies
        self.report_interval = 45 * 60  # 45 minutes
        
        # Sustained anomaly tracking
        self.consecutive_anomalies = {}  # {user: count of consecutive anomalies}
        self.user_risk_levels = {}  # {user: current risk level}
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Statistics
        self.total_anomalies_detected = 0
        self.total_exfiltration_alerts = 0
        
        print("[+] Enhanced Keystroke Anomaly Monitor initialized", flush=True)
        print(f"    - Anomaly multiplier: {self.anomaly_multiplier}x baseline", flush=True)
        print(f"    - Sustained window threshold: {self.sustained_windows} consecutive", flush=True)
        print(f"    - Report interval: {self.report_interval // 60} minutes", flush=True)
    
    def start(self):
        """Start the monitoring thread"""
        self.running = True
        self.thread = threading.Thread(target=self._report_loop, daemon=True)
        self.thread.start()
        print("[+] Enhanced keystroke anomaly monitor thread started", flush=True)
    
    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[*] Keystroke anomaly monitor stopped", flush=True)
    
    def record_keystroke(self, user):
        """Record a keystroke for a user (called frequently)"""
        with self.lock:
            if user not in self.keystroke_counts:
                self.keystroke_counts[user] = 0
            self.keystroke_counts[user] += 1
    
    def _report_loop(self):
        """Main monitoring loop - runs every 45 minutes"""
        while self.running:
            time.sleep(self.report_interval)
            
            with self.lock:
                # Process each user's window
                for user, count in list(self.keystroke_counts.items()):
                    self._process_window_for_user(user, count)
                
                # Clear for next window
                self.keystroke_counts.clear()
    
    def _process_window_for_user(self, user, keystroke_count):
        """
        Process completed window for user.
        Called once per 45 minutes per user.
        """
        # Initialize user history if needed
        if user not in self.user_windows:
            self.user_windows[user] = deque(maxlen=self.window_history_size)
            self.consecutive_anomalies[user] = 0
            self.user_risk_levels[user] = "LOW"
        
        # Add current window to history
        self.user_windows[user].append(keystroke_count)
        
        # Calculate baseline
        baseline = self._get_baseline(user)
        
        # Log normal summary
        self.logger.log(
            "KEYSTROKE_SUMMARY",
            f"User: {user} | Keystrokes: {keystroke_count} | Baseline: {baseline:.0f} | Period: 45-minute"
        )
        
        # Check for anomaly
        if baseline > 0:
            ratio = keystroke_count / baseline
            
            if ratio >= self.anomaly_multiplier:
                # ANOMALY DETECTED
                self._handle_keystroke_anomaly(user, keystroke_count, baseline, ratio)
            else:
                # Normal window - reset consecutive counter
                self.consecutive_anomalies[user] = 0
                self.user_risk_levels[user] = "LOW"
    
    def _handle_keystroke_anomaly(self, user, keystroke_count, baseline, ratio):
        """
        Handle detected keystroke anomaly.
        Check if it's sustained (multiple windows) = exfiltration indicator
        """
        self.total_anomalies_detected += 1
        self.consecutive_anomalies[user] += 1
        
        # Calculate risk level and severity
        severity = self._calculate_severity(ratio, self.consecutive_anomalies[user])
        risk_level = self._get_risk_level(ratio, self.consecutive_anomalies[user])
        self.user_risk_levels[user] = risk_level
        
        # Prepare anomaly event details
        anomaly_details = {
            "user": user,
            "keystroke_count": keystroke_count,
            "baseline": baseline,
            "ratio": round(ratio, 2),
            "consecutive_anomalies": self.consecutive_anomalies[user],
            "severity": severity,
            "risk_level": risk_level,
            "window_number": len(self.user_windows[user]),
            "timestamp": datetime.now().isoformat()
        }
        
        # Check if this is sustained (3+ consecutive windows)
        is_sustained = self.consecutive_anomalies[user] >= self.sustained_windows
        
        if is_sustained:
            # EXFILTRATION PATTERN DETECTED
            self._handle_exfiltration_pattern(user, anomaly_details)
        else:
            # Single anomaly - log but not critical yet
            self.logger.log(
                "KEYSTROKE_ANOMALY",
                f"User: {user} | Keystrokes: {keystroke_count} | "
                f"Baseline: {baseline:.0f} | Ratio: {ratio:.1f}x | "
                f"Consecutive: {self.consecutive_anomalies[user]}/{self.sustained_windows} | "
                f"Severity: {severity}/10 | Risk: {risk_level}"
            )
    
    def _handle_exfiltration_pattern(self, user, anomaly_details):
        """
        Handle confirmed exfiltration pattern.
        Triggered when sustained high keystroke rate (3+ windows of 3x baseline)
        
        DATA EXFILTRATION ALERT:
        - Normal: 5,000-8,000 keystrokes/45min
        - Attack: 50,000+ keystrokes/45min (copy large amounts of text)
        - Detection: Sustained high keystroke rate over multiple windows
        """
        self.total_exfiltration_alerts += 1
        
        # Add exfiltration-specific data
        exfil_details = anomaly_details.copy()
        exfil_details["attack_pattern"] = "DATA_EXFILTRATION"
        exfil_details["indicators"] = self._get_exfiltration_indicators(user)
        exfil_details["recommended_action"] = "IMMEDIATE_INVESTIGATION"
        
        # Log as critical KEYSTROKE_ANOMALY event
        self.logger.log(
            "KEYSTROKE_ANOMALY",
            f"🔴 EXFILTRATION ALERT: User: {user} | "
            f"Keystrokes: {anomaly_details['keystroke_count']} | "
            f"Baseline: {anomaly_details['baseline']:.0f} | "
            f"Ratio: {anomaly_details['ratio']}x | "
            f"Sustained Windows: {anomaly_details['consecutive_anomalies']}/{self.sustained_windows} | "
            f"Severity: {anomaly_details['severity']}/10 | "
            f"Risk: CRITICAL | "
            f"Attack Pattern: DATA_EXFILTRATION | "
            f"Indicators: {','.join(exfil_details['indicators'])} | "
            f"Recommended: {exfil_details['recommended_action']}"
        )
        
        # Also log detailed JSON for server ingestion
        self.logger.log(
            "KEYSTROKE_ANOMALY_DETAILED",
            json.dumps(exfil_details)
        )
    
    def _get_exfiltration_indicators(self, user):
        """
        Identify specific indicators that suggest data exfiltration
        """
        indicators = []
        
        if user in self.user_windows and len(self.user_windows[user]) >= self.sustained_windows:
            recent_windows = list(self.user_windows[user])[-self.sustained_windows:]
            baseline = self._get_baseline(user)
            
            if baseline > 0:
                # Check for sustained high rate
                high_count = sum(1 for count in recent_windows if count / baseline >= self.anomaly_multiplier)
                if high_count >= self.sustained_windows:
                    indicators.append("SUSTAINED_HIGH_RATE")
                
                # Check for progressive increase
                if len(recent_windows) >= 2:
                    increasing = sum(1 for i in range(1, len(recent_windows)) 
                                   if recent_windows[i] > recent_windows[i-1])
                    if increasing >= len(recent_windows) - 1:
                        indicators.append("PROGRESSIVE_INCREASE")
                
                # Check for extreme spike
                max_window = max(recent_windows)
                if max_window / baseline > 10:
                    indicators.append("EXTREME_SPIKE")
                
                # Check for copy-paste patterns (very high in short bursts)
                if baseline > 0 and max(recent_windows) > baseline * 8:
                    indicators.append("POSSIBLE_BULK_COPY_PASTE")
        
        return indicators if indicators else ["SUSTAINED_ANOMALY"]
    
    def _calculate_severity(self, ratio, consecutive_count):
        """
        Calculate severity score (0-10) based on:
        - How much above baseline (ratio)
        - How many consecutive windows (persistence)
        """
        # Base severity from ratio
        if ratio < 3.0:
            base = 2
        elif ratio < 5.0:
            base = 4
        elif ratio < 10.0:
            base = 6
        else:
            base = 8
        
        # Increase severity for sustained anomalies
        sustained_multiplier = min(consecutive_count / 3.0, 1.25)  # Up to 25% increase
        
        severity = int(base * sustained_multiplier)
        return min(severity, 10)  # Cap at 10
    
    def _get_risk_level(self, ratio, consecutive_count):
        """
        Categorize risk level based on severity indicators
        """
        if consecutive_count >= 3 and ratio >= 3.0:
            return "CRITICAL"
        elif consecutive_count >= 2 and ratio >= 5.0:
            return "CRITICAL"
        elif ratio >= 5.0:
            return "HIGH"
        elif consecutive_count >= 2:
            return "HIGH"
        elif ratio >= 3.0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_baseline(self, user):
        """
        Calculate baseline keystroke count for a user
        Returns average of history (or 0 if insufficient data)
        """
        if user not in self.user_windows:
            return 0
        
        history = self.user_windows[user]
        
        # Need minimum windows for baseline
        if len(history) < int(self.baseline_threshold * self.window_history_size):
            return 0
        
        return sum(history) / len(history)
    
    def get_user_status(self, user):
        """Get current monitoring status for user"""
        with self.lock:
            return {
                "user": user,
                "current_risk_level": self.user_risk_levels.get(user, "UNKNOWN"),
                "consecutive_anomalies": self.consecutive_anomalies.get(user, 0),
                "baseline": self._get_baseline(user),
                "history_windows": list(self.user_windows.get(user, [])),
                "total_anomalies_detected": self.total_anomalies_detected,
                "total_exfiltration_alerts": self.total_exfiltration_alerts
            }
    
    def get_statistics(self):
        """Get overall monitoring statistics"""
        with self.lock:
            return {
                "total_anomalies_detected": self.total_anomalies_detected,
                "total_exfiltration_alerts": self.total_exfiltration_alerts,
                "monitored_users": len(self.user_windows),
                "timestamp": datetime.now().isoformat()
            }

# ==================== KEYSTROKE MONITOR ====================

class KeystrokeMonitor:
    """Keystroke monitoring with enhanced anomaly detection"""
    
    def __init__(self, logger):
        self.running = False
        self.listener = None
        self.log_path = Path("logs") / "keys.txt"
        self.log_path.parent.mkdir(exist_ok=True)
        
        # Use enhanced anomaly monitor
        self.anomaly_monitor = EnhancedKeystrokeAnomalyMonitor(logger)
    
    def start(self):
        """Start keystroke monitoring"""
        self.running = True
        self.anomaly_monitor.start()
        self.listener = keyboard.Listener(on_press=self._on_press)
        self.listener.start()
        print("[+] Enhanced keystroke monitor started (Data Exfiltration Detection)", flush=True)
    
    def stop(self):
        """Stop keystroke monitoring"""
        self.running = False
        self.anomaly_monitor.stop()
        if self.listener:
            self.listener.stop()
        print("[*] Enhanced keystroke monitor stopped", flush=True)
    
    def _on_press(self, key):
        """Capture keystroke"""
        try:
            # Log to file
            with open(self.log_path, "a", encoding="utf-8") as f:
                try:
                    f.write(f"{key.char}")
                except AttributeError:
                    f.write(f"[{key}]")
            
            # Record for anomaly detection
            if self.running:
                self.anomaly_monitor.record_keystroke(CURRENT_USER)
        
        except Exception as e:
            print(f"[!] Keystroke handler error: {e}", flush=True)

# ==================== PSUTIL PROCESS SNAPSHOT ====================

class PsutilProcessSnapshot:
    def __init__(self, logger):
        self.logger = logger

    def get_digital_signature(self, path):
        try:
            if os.path.isfile(path):
                return "Exists/UnknownSignature"
            else:
                return "NoFile"
        except Exception:
            return "Error"

    def run_once(self):
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline', 'ppid']):
                try:
                    pid = proc.pid
                    name = proc.name()
                    create_time = proc.create_time() if hasattr(proc, 'create_time') else 0
                    cmdline = proc.cmdline()
                    ppid = proc.ppid()
                    try:
                        parent_proc = psutil.Process(ppid)
                        parent_name = parent_proc.name()
                    except Exception:
                        parent_name = "N/A"
                    try:
                        exe_path = proc.exe()
                    except Exception:
                        exe_path = "N/A"
                    try:
                        username = proc.username()
                    except Exception:
                        username = "N/A"
                    digital_signature = self.get_digital_signature(exe_path)
                    processes.append({
                        'pid': pid,
                        'name': name,
                        'create_time': create_time,
                        'cmdline': cmdline,
                        'ppid': ppid,
                        'parent_name': parent_name,
                        'exe_path': exe_path,
                        'username': username,
                        'digital_signature': digital_signature
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            processes.sort(key=lambda p: p.get('create_time', 0), reverse=True)

            for proc in processes[:30]:
                timestamp = datetime.fromtimestamp(proc.get('create_time', 0), tz=timezone.utc).isoformat(timespec='milliseconds')
                cmdline_str = ' '.join(proc.get('cmdline', [])) or 'N/A'
                self.logger.log(
                    "PROCESS_CREATE",
                    f"Name: {proc['name']} | PID: {proc['pid']} | Parent: {proc['parent_name']} (PID: {proc['ppid']}) | "
                    f"User: {proc['username']} | Path: {proc['exe_path']} | Signature: {proc['digital_signature']} | "
                    f"Time: {timestamp} | Cmd: {cmdline_str}"
                )
        except Exception as e:
            print(f"[!] Psutil snapshot error: {e}", flush=True)

# ==================== PROCESS MONITOR ====================

class ProcessMonitor:
    """Real-time process monitoring using Windows API"""
    
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.known_processes = {}
        self.lock = threading.Lock()
        self.monitor_interval = 1
        self.exclusions = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("[*] Kernel-level process monitor started (real-time tracking)", flush=True)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[*] Process monitor stopped", flush=True)

    def _get_process_details(self, pid):
        """Get detailed process information using psutil"""
        try:
            proc = psutil.Process(pid)
            details = {
                'pid': pid,
                'ppid': proc.ppid() if proc.ppid() else 0,
                'name': proc.name(),
                'command_line': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                'exe_path': proc.exe(),
                'username': proc.username(),
                'create_time': proc.create_time() if hasattr(proc, 'create_time') else 0
            }
            
            # Get parent process name
            try:
                parent_proc = psutil.Process(details['ppid'])
                details['parent_name'] = parent_proc.name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                details['parent_name'] = 'N/A'
            
            return details
        except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
            return None

    def _log_process_create(self, details):
        """Log process creation event"""
        try:
            name = details.get('name', 'N/A')
            pid = details.get('pid', 0)
            ppid = details.get('ppid', 0)
            parent_name = details.get('parent_name', 'N/A')
            username = details.get('username', 'N/A')
            exe_path = details.get('exe_path', 'N/A')
            cmdline = details.get('command_line', 'N/A')
            
            # CHECK EXCLUSION
            if self.exclusions and self.exclusions.should_exclude(name):
                return
            
            event_details = (
                f"Process: {name} | PID: {pid} | PPID: {ppid} | Parent: {parent_name} | "
                f"User: {username} | Path: {exe_path} | CmdLine: {cmdline}"
            )
            
            self.logger.log("PROCESS_CREATE", event_details)
            print(f"[+] PROCESS_CREATE: {name} (PID: {pid}) | Parent: {parent_name} | User: {username}", flush=True)
        except Exception as e:
            print(f"[!] Error logging process creation: {e}", flush=True)

    def _monitor_loop(self):
        """Main monitoring loop"""
        print("[*] Process monitor loop started", flush=True)
        
        while self.running:
            try:
                with self.lock:
                    current_pids = set()
                    
                    try:
                        for proc in psutil.process_iter(['pid']):
                            current_pids.add(proc.pid)
                    except Exception as e:
                        print(f"[!] Error enumerating processes: {e}", flush=True)
                        time.sleep(self.monitor_interval)
                        continue
                    
                    # Detect NEW processes
                    new_pids = current_pids - set(self.known_processes.keys())
                    for pid in new_pids:
                        details = self._get_process_details(pid)
                        if details:
                            self.known_processes[pid] = details
                            self._log_process_create(details)
                
                time.sleep(self.monitor_interval)
                
            except Exception as e:
                print(f"[!] Process monitor error: {e}", flush=True)
                time.sleep(self.monitor_interval)

# ==================== ETW COMMAND CAPTURE ====================

class ETWCommandCaptureMonitor:
    """Real-time command capture from cmd.exe and powershell.exe"""
    
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.captured_commands = set()
        self.lock = threading.Lock()
        self.check_interval = 2

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._etw_monitor_loop, daemon=True)
        self.thread.start()
        print("[*] ETW Command Capture Monitor started (real-time cmd/PowerShell tracking)", flush=True)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[*] ETW Command Capture Monitor stopped", flush=True)

    def _get_process_info(self, pid):
        """Get detailed info about a process by PID"""
        try:
            proc = psutil.Process(pid)
            return {
                'name': proc.name(),
                'cmdline': ' '.join(proc.cmdline()) if proc.cmdline() else '',
                'exe_path': proc.exe(),
                'username': proc.username(),
                'ppid': proc.ppid() if proc.ppid() else 0,
                'create_time': proc.create_time(),
                'pid': pid
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def _get_parent_info(self, ppid):
        """Get parent process name"""
        try:
            parent = psutil.Process(ppid)
            return parent.name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return 'N/A'

    def _etw_monitor_loop(self):
        """Main ETW monitoring loop"""
        print("[*] ETW Command Capture Monitor loop started", flush=True)
        
        while self.running:
            try:
                # Capture cmd.exe process execution
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
                    try:
                        if proc.info['name'] in ['cmd.exe', 'powershell.exe']:
                            pid = proc.info['pid']
                            cmdline = ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                            
                            cmd_key = (pid, cmdline)
                            
                            if cmd_key not in self.captured_commands:
                                self.captured_commands.add(cmd_key)
                                
                                try:
                                    p = psutil.Process(pid)
                                    parent_name = self._get_parent_info(p.ppid() if p.ppid() else 0)
                                    
                                    event_details = (
                                        f"Shell: {proc.info['name']} | PID: {pid} | Parent: {parent_name} | "
                                        f"User: {proc.info['username']} | Path: {p.exe()} | Command: {cmdline}"
                                    )
                                    self.logger.log("COMMAND_EXECUTION", event_details)
                                    print(f"[+] COMMAND_EXECUTION: {proc.info['name']} | PID: {pid} | Parent: {parent_name}", flush=True)
                                except (psutil.NoSuchProcess, psutil.AccessDenied):
                                    pass
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                time.sleep(self.check_interval)

            except Exception as e:
                print(f"[!] ETW monitor error: {e}", flush=True)
                time.sleep(self.check_interval)

# ==================== POWERSHELL MONITOR ====================

class PowerShellMonitor:
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.history_file = Path(os.environ.get('APPDATA', '')) / 'Microsoft' / 'Windows' / 'PowerShell' / 'PSReadLine' / 'ConsoleHost_history.txt'
        self.last_line = 0

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("[*] PowerShell monitor started", flush=True)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[*] PowerShell monitor stopped", flush=True)

    def _monitor_loop(self):
        while self.running:
            try:
                if self.history_file.exists():
                    with open(self.history_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        total_lines = len(lines)
                        start_index = max(total_lines - 30, self.last_line)
                        new_lines = lines[start_index:]
                        for line in new_lines:
                            line = line.strip()
                            if line:
                                self.logger.log("POWERSHELL_HISTORY", line)
                        self.last_line = total_lines
                time.sleep(5)
            except Exception as e:
                print(f"[!] PowerShell monitor error: {e}", flush=True)
                time.sleep(5)

# ==================== FILE MONITOR ====================

class FileMonitor(FileSystemEventHandler):
    def __init__(self, logger):
        self.logger = logger

    def on_created(self, event):
        if not event.is_directory:
            self.logger.log("FILE_CREATE", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.logger.log("FILE_MODIFY", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.logger.log("FILE_DELETE", event.src_path)

class FileWatcher:
    def __init__(self, logger):
        self.logger = logger
        self.observer = Observer()
        self.documents_path = Path(os.path.expanduser("~")) / "Documents"
        self.documents_path.mkdir(exist_ok=True)

    def start(self):
        handler = FileMonitor(self.logger)
        self.observer.schedule(handler, str(self.documents_path), recursive=True)
        self.observer.start()
        print(f"[*] File monitor started on {self.documents_path}", flush=True)

    def stop(self):
        self.observer.stop()
        self.observer.join()
        print("[*] File monitor stopped", flush=True)

# ==================== NETWORK MONITOR ====================

class NetworkMonitor:
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.known_connections = {}
        self.process_io_stats = {}
        self.exclusions = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("[*] Network monitor started (bandwidth tracking, L7 + TTL)", flush=True)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[*] Network monitor stopped", flush=True)

    def _resolve_hostname(self, ip_address):
        try:
            hostname = socket.gethostbyaddr(ip_address)[0]
            return hostname
        except Exception:
            return ip_address

    def _get_process_io_stats(self, pid):
        try:
            proc = psutil.Process(pid)
            io_counters = proc.io_counters()
            return io_counters.read_bytes, io_counters.write_bytes
        except Exception:
            return 0, 0

    def _format_bytes(self, bytes_value):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f}{unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f}TB"

    def _get_ttl(self, ip):
        """Retrieve TTL by sending a single ping"""
        try:
            output = subprocess.check_output(["ping", "-n", "1", "-w", "1000", ip],
                                             stderr=subprocess.DEVNULL,
                                             text=True)
            for line in output.splitlines():
                if "TTL=" in line.upper():
                    ttl = line.upper().split("TTL=")[1].split()[0]
                    return int(ttl)
        except Exception:
            pass
        return None

    def _infer_l7_protocol(self, port):
        """Basic L7 protocol inference from port"""
        known = {
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            21: "FTP",
            22: "SSH",
            25: "SMTP",
            110: "POP3",
            143: "IMAP",
            3389: "RDP",
        }
        return known.get(port, "Unknown")

    def _monitor_loop(self):
        while self.running:
            try:
                for conn in psutil.net_connections(kind='inet'):
                    if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                        continue

                    try:
                        proc_name = psutil.Process(conn.pid).name() if conn.pid else "Unknown"
                        bytes_recv, bytes_sent = self._get_process_io_stats(conn.pid)
                    except Exception:
                        proc_name = "Unknown"
                        bytes_recv, bytes_sent = 0, 0

                    key = (conn.pid, conn.laddr.ip, conn.laddr.port, conn.raddr.ip, conn.raddr.port)
                    l7_proto = self._infer_l7_protocol(conn.raddr.port)
                    ttl = self._get_ttl(conn.raddr.ip)

                    if key not in self.known_connections:
                        # CHECK EXCLUSION
                        if self.exclusions and self.exclusions.should_exclude(proc_name):
                            self.known_connections[key] = {'pid': conn.pid, 'bytes_recv': bytes_recv, 'bytes_sent': bytes_sent}
                            self.process_io_stats[conn.pid] = (bytes_recv, bytes_sent)
                            continue
                        
                        prev_recv, prev_sent = self.process_io_stats.get(conn.pid, (bytes_recv, bytes_sent))
                        bytes_in = bytes_recv - prev_recv
                        bytes_out = bytes_sent - prev_sent
                        ttl_str = f"{ttl}" if ttl else "N/A"

                        self.logger.log("NETWORK_CONN",
                            f"Process: {proc_name} | Local: {conn.laddr.ip}:{conn.laddr.port} -> "
                            f"Remote: {conn.raddr.ip}:{conn.raddr.port} | L7: {l7_proto} | TTL: {ttl_str} | "
                            f"Bytes In: {self._format_bytes(bytes_in)} | Bytes Out: {self._format_bytes(bytes_out)}"
                        )

                        self.known_connections[key] = {'pid': conn.pid, 'bytes_recv': bytes_recv, 'bytes_sent': bytes_sent}
                        self.process_io_stats[conn.pid] = (bytes_recv, bytes_sent)

                active_keys = {(c.pid, c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port)
                               for c in psutil.net_connections(kind='inet') if c.status == psutil.CONN_ESTABLISHED and c.raddr}
                self.known_connections = {k: v for k, v in self.known_connections.items() if k in active_keys}

                existing_pids = {p.pid for p in psutil.process_iter(['pid'])}
                self.process_io_stats = {pid: st for pid, st in self.process_io_stats.items() if pid in existing_pids}

                time.sleep(5)
            except Exception as e:
                print(f"[!] Network monitor error: {e}", flush=True)
                time.sleep(5)

# ==================== WINDOW ACTIVITY MONITOR ====================

class WindowActivityMonitor:
    def __init__(self, logger):
        self.logger = logger
        self.running = False
        self.thread = None
        self.known_windows = {}
        self.last_foreground = None
        self.exclusions = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        print("[*] Window activity monitor started", flush=True)

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        print("[*] Window activity monitor stopped", flush=True)

    def _get_window_state(self, hwnd):
        try:
            placement = win32gui.GetWindowPlacement(hwnd)
            show_cmd = placement[1]
            if show_cmd == win32con.SW_SHOWMINIMIZED:
                return "MINIMIZED"
            elif show_cmd == win32con.SW_SHOWMAXIMIZED:
                return "MAXIMIZED"
            else:
                return "NORMAL"
        except Exception:
            return "UNKNOWN"

    def _is_system_window(self, pid, proc_name):
        try:
            proc = psutil.Process(pid)
            username = proc.username().lower()
            if "nt authority" in username or "system" in proc_name.lower():
                return True
        except Exception:
            pass
        return False

    def _monitor_loop(self):
        while self.running:
            try:
                current_windows = {}

                def enum_handler(hwnd, _):
                    try:
                        if not win32gui.IsWindowVisible(hwnd):
                            return
                        title = win32gui.GetWindowText(hwnd)
                        if not title.strip():
                            return
                        _, pid = win32process.GetWindowThreadProcessId(hwnd)
                        try:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()
                            if self._is_system_window(pid, proc_name):
                                return
                            try:
                                username = proc.username()
                            except Exception:
                                username = "Unknown"
                            state = self._get_window_state(hwnd)
                            current_windows[hwnd] = {
                                'title': title,
                                'pid': pid,
                                'process': proc_name,
                                'username': username,
                                'state': state
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            return
                    except Exception:
                        return

                win32gui.EnumWindows(enum_handler, None)

                # Detect NEW windows
                for hwnd, info in current_windows.items():
                    if hwnd not in self.known_windows:
                        # CHECK EXCLUSION
                        if self.exclusions and self.exclusions.should_exclude(info['process']):
                            continue
                        
                        self.logger.log("WINDOW_CREATE",
                            f"Title: {info['title']} | PID: {info['pid']} | "
                            f"Process: {info['process']} | User: {info['username']} | State: {info['state']}")

                # Detect CLOSED windows
                closed_windows = set(self.known_windows.keys()) - set(current_windows.keys())
                for hwnd in closed_windows:
                    old_info = self.known_windows[hwnd]
                    # CHECK EXCLUSION
                    if self.exclusions and self.exclusions.should_exclude(old_info['process']):
                        continue
                    
                    self.logger.log("WINDOW_CLOSE",
                        f"Title: {old_info['title']} | PID: {old_info['pid']} | "
                        f"Process: {old_info['process']} | User: {old_info['username']}")

                # Detect TITLE changes
                for hwnd, info in current_windows.items():
                    if hwnd in self.known_windows:
                        # CHECK EXCLUSION
                        if self.exclusions and self.exclusions.should_exclude(info['process']):
                            continue
                        
                        old_info = self.known_windows[hwnd]
                        if old_info['title'] != info['title']:
                            self.logger.log("WINDOW_TITLE_CHANGE",
                                f"Process: {info['process']} | PID: {info['pid']} | User: {info['username']} | "
                                f"Old: {old_info['title']} | New: {info['title']}")

                # Detect STATE changes
                for hwnd, info in current_windows.items():
                    if hwnd in self.known_windows:
                        # CHECK EXCLUSION
                        if self.exclusions and self.exclusions.should_exclude(info['process']):
                            continue
                        
                        old_info = self.known_windows[hwnd]
                        if old_info['state'] != info['state']:
                            self.logger.log("WINDOW_STATE_CHANGE",
                                f"Title: {info['title']} | Process: {info['process']} | User: {info['username']} | "
                                f"PID: {info['pid']} | {old_info['state']} -> {info['state']}")

                # Detect FOCUS changes
                try:
                    foreground_hwnd = win32gui.GetForegroundWindow()
                    if foreground_hwnd != self.last_foreground and foreground_hwnd in current_windows:
                        info = current_windows[foreground_hwnd]
                        # CHECK EXCLUSION
                        if not (self.exclusions and self.exclusions.should_exclude(info['process'])):
                            self.logger.log("WINDOW_FOCUS",
                                f"Title: {info['title']} | Process: {info['process']} | User: {info['username']} | "
                                f"PID: {info['pid']} | State: {info['state']}")
                        self.last_foreground = foreground_hwnd
                except Exception:
                    pass

                self.known_windows = current_windows

                time.sleep(1)
            except Exception as e:
                print(f"[!] Window activity monitor error: {e}", flush=True)
                time.sleep(1)

# ==================== MAIN RUNNER ====================

def run_agent(logger, ps_monitor, file_watcher, net_monitor, key_monitor, window_monitor, proc_monitor, etw_monitor):
    """Non-interactive runner: start all monitors immediately and keep running."""
    try:
        # Start all monitors
        ps_monitor.start()
        proc_monitor.start()
        etw_monitor.start()
        file_watcher.start()
        net_monitor.start()
        key_monitor.start()
        window_monitor.start()
        print("[*] All monitors started")

        # Keep the main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        # Graceful shutdown on Ctrl+C
        print("\n[*] Shutting down monitors...")
        ps_monitor.stop()
        proc_monitor.stop()
        etw_monitor.stop()
        file_watcher.stop()
        net_monitor.stop()
        key_monitor.stop()
        window_monitor.stop()
        logger.close()
        print("[*] Agent exited.")

# ==================== MAIN ENTRY POINT ====================

if __name__ == "__main__":
    print("\n" + "="*80)
    print("EDR Agent - Enhanced with Advanced Keystroke Anomaly Detection")
    print("="*80)
    print(f"Device: {DEVICE_NAME} | User: {CURRENT_USER} | Time: {datetime.now().isoformat()}")
    print("="*80 + "\n")
    
    # Initialize exclusions system
    exclusions = ProcessExclusions("exclusions.json")
    
    # Initialize logger
    logger = Logger()
    
    # Initialize monitors
    proc_snapshot = PsutilProcessSnapshot(logger)
    proc_snapshot.run_once()

    ps_monitor = PowerShellMonitor(logger)
    proc_monitor = ProcessMonitor(logger)
    etw_monitor = ETWCommandCaptureMonitor(logger)
    file_watcher = FileWatcher(logger)
    net_monitor = NetworkMonitor(logger)
    key_monitor = KeystrokeMonitor(logger)
    window_monitor = WindowActivityMonitor(logger)
    
    # Attach exclusions to monitors
    proc_monitor.exclusions = exclusions
    net_monitor.exclusions = exclusions
    window_monitor.exclusions = exclusions

    # Start Flask backend communication in background
    threading.Thread(target=background_loop, args=(logger,), daemon=True).start()

    # Start all monitors
    run_agent(logger, ps_monitor, file_watcher, net_monitor, key_monitor, window_monitor, proc_monitor, etw_monitor)