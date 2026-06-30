# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify
import subprocess
import re
import json
import time
import threading
import csv
import io

app = Flask(__name__)
SNMPWALK = "/usr/bin/snmpwalk"

with open('config.json', 'r') as f:
    CONFIG = json.load(f)

SWITCHES = CONFIG['switches']
SETTINGS = CONFIG['settings']

# Cache for MAC tables
mac_cache = {}
mac_cache_time = {}

# ARP cache
arp_cache = {}
arp_cache_time = 0

# Search status
search_status = {
    "active": False,
    "progress": 0,
    "total": 0,
    "results": [],
    "message": ""
}

def get_arp_table():
    """Get full ARP table using arp-scan (cached)."""
    global arp_cache, arp_cache_time
    
    now = time.time()
    if now - arp_cache_time < SETTINGS['arp_scan_interval']:
        return arp_cache
    
    arp = {}
    try:
        result = subprocess.run(
            ['sudo', 'arp-scan', '--localnet', '--quiet'],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            match = re.search(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)', line)
            if match:
                ip = match.group(1)
                mac_raw = match.group(2).replace(':', '').upper()
                arp[mac_raw] = ip
    except Exception as e:
        print(f"arp-scan error: {e}")
    
    arp_cache = arp
    arp_cache_time = now
    return arp

def get_switch_data(switch, force_refresh=False):
    """Get MAC table from switch (cached)."""
    ip = switch['ip']
    community = switch['community']
    exclude_ports = switch.get('exclude_ports', [])
    exclude_macs = switch.get('exclude_macs', [])
    
    cache_key = f"{ip}_{community}"
    now = time.time()
    
    # Check cache
    if not force_refresh and cache_key in mac_cache:
        cache_age = now - mac_cache_time.get(cache_key, 0)
        if cache_age < SETTINGS.get('cache_ttl', 60):
            print(f"Cache hit: {ip} (age: {cache_age:.0f}s)")
            return mac_cache[cache_key]
    
    print(f"Cache miss: {ip}, fetching...")
    
    try:
        mac_walk = subprocess.run(
            [SNMPWALK, "-v", "2c", "-c", community, ip, "1.3.6.1.2.1.17.7.1.2.2.1"],
            capture_output=True, text=True, timeout=SETTINGS['snmp_timeout']
        ).stdout.splitlines()
    except subprocess.TimeoutExpired:
        print(f"Timeout: {ip}")
        return []

    port_walk = subprocess.run(
        [SNMPWALK, "-v", "2c", "-c", community, ip, "1.3.6.1.2.1.31.1.1.1.1"],
        capture_output=True, text=True, timeout=SETTINGS['snmp_timeout']
    ).stdout.splitlines()

    port_names = {}
    for line in port_walk:
        m = re.search(r'\.1\.1\.1\.(\d+)\s*=\s*STRING:\s*"(.+?)"', line)
        if m:
            port_names[m.group(1)] = m.group(2)

    all_entries = []
    for line in mac_walk:
        if 'INTEGER:' not in line:
            continue
        
        numbers = re.findall(r'\d+', line)
        if len(numbers) >= 7:
            port = numbers[-1]
            
            if port in exclude_ports:
                continue
            
            mac_numbers = numbers[-7:-1]
            
            hex_bytes = []
            for num_str in mac_numbers:
                try:
                    num = int(num_str)
                    if 0 <= num <= 255:
                        hex_bytes.append(f"{num:02X}")
                except:
                    pass
            
            if len(hex_bytes) == 6:
                mac_raw = ''.join(hex_bytes)
                mac_formatted = '-'.join(hex_bytes)
                
                if mac_formatted in exclude_macs:
                    continue
                
                port_name = port_names.get(port, f"Port {port}")
                all_entries.append({
                    "mac_raw": mac_raw,
                    "mac": mac_formatted,
                    "port": port_name
                })

    # Save to cache
    mac_cache[cache_key] = all_entries
    mac_cache_time[cache_key] = now
    return all_entries

def search_all_switches(query):
    """Perform search across all switches with progress tracking."""
    global search_status
    
    search_status["active"] = True
    search_status["progress"] = 0
    search_status["total"] = len(SWITCHES)
    search_status["results"] = []
    search_status["message"] = "Starting search..."
    
    results = []
    arp = get_arp_table()
    
    for i, switch in enumerate(SWITCHES):
        search_status["message"] = f"Searching {switch['name']}..."
        search_status["progress"] = i + 1
        
        entries = get_switch_data(switch)
        for entry in entries:
            ip = arp.get(entry["mac_raw"], "Not found")
            if query in entry["mac"] or query in ip:
                results.append({
                    "switch": switch['name'],
                    "port": entry["port"],
                    "mac": entry["mac"],
                    "ip": ip
                })
        
        time.sleep(0.1)
    
    search_status["results"] = results
    search_status["message"] = f"Found {len(results)} entries"
    search_status["active"] = False
    return results

@app.route('/')
def index():
    return render_template('index.html', switches=SWITCHES)

@app.route('/api/switch/<int:switch_id>')
def get_switch(switch_id):
    if switch_id < 0 or switch_id >= len(SWITCHES):
        return jsonify({"error": "Switch not found"}), 404

    switch = SWITCHES[switch_id]
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    entries = get_switch_data(switch, force_refresh)
    arp = get_arp_table()
    
    result = []
    for entry in entries:
        ip = arp.get(entry["mac_raw"], "Not found")
        result.append({
            "port": entry["port"],
            "mac": entry["mac"],
            "ip": ip
        })
    
    ports = sorted(set([item['port'] for item in result]))

    return jsonify({
        "name": switch['name'],
        "ip": switch['ip'],
        "ports": ports,
        "data": result
    })

@app.route('/api/search', methods=['POST'])
def search():
    query = request.json.get('query', '').strip().upper()
    if not query:
        return jsonify({"error": "Enter search query"}), 400
    
    thread = threading.Thread(target=search_all_switches, args=(query,))
    thread.daemon = True
    thread.start()
    
    return jsonify({"status": "started"})

@app.route('/api/search/progress')
def search_progress():
    global search_status
    return jsonify({
        "active": search_status["active"],
        "progress": search_status["progress"],
        "total": search_status["total"],
        "message": search_status["message"],
        "results": search_status["results"] if not search_status["active"] else []
    })

@app.route('/api/cache/status', methods=['GET'])
def cache_status():
    """Return current cache status."""
    global mac_cache, mac_cache_time, arp_cache, arp_cache_time
    now = time.time()
    
    active_mac_entries = 0
    oldest_mac_age = None
    for key, timestamp in mac_cache_time.items():
        if now - timestamp < SETTINGS.get('cache_ttl', 60):
            active_mac_entries += 1
            age = now - timestamp
            if oldest_mac_age is None or age > oldest_mac_age:
                oldest_mac_age = age
    
    arp_age = now - arp_cache_time if arp_cache_time else None
    arp_active = arp_age is not None and arp_age < SETTINGS.get('arp_scan_interval', 120)
    
    return jsonify({
        "mac_entries": len(mac_cache),
        "active_mac_entries": active_mac_entries,
        "oldest_mac_age": round(oldest_mac_age) if oldest_mac_age else None,
        "ttl": SETTINGS.get('cache_ttl', 60),
        "arp_active": arp_active,
        "arp_age": round(arp_age) if arp_age else None
    })

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Clear all caches."""
    global mac_cache, mac_cache_time, arp_cache, arp_cache_time
    mac_cache = {}
    mac_cache_time = {}
    arp_cache = {}
    arp_cache_time = 0
    return jsonify({"status": "Cache cleared"})

# --- CSV Export ---
@app.route('/api/switch/<int:switch_id>/csv')
def export_switch_csv(switch_id):
    """Export switch data as CSV."""
    if switch_id < 0 or switch_id >= len(SWITCHES):
        return jsonify({"error": "Switch not found"}), 404

    switch = SWITCHES[switch_id]
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    entries = get_switch_data(switch, force_refresh)
    arp = get_arp_table()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Port', 'MAC', 'IP'])
    
    for entry in entries:
        ip = arp.get(entry["mac_raw"], "Not found")
        writer.writerow([entry["port"], entry["mac"], ip])
    
    response = app.response_class(
        response=output.getvalue(),
        status=200,
        mimetype='text/csv'
    )
    response.headers["Content-Disposition"] = f"attachment; filename={switch['name']}_port-mac-ip.csv"
    return response

@app.route('/api/export/all')
def export_all_csv():
    """Export all switches data as a single CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Switch', 'Port', 'MAC', 'IP'])
    
    arp = get_arp_table()
    for switch in SWITCHES:
        entries = get_switch_data(switch)
        for entry in entries:
            ip = arp.get(entry["mac_raw"], "Not found")
            writer.writerow([switch['name'], entry["port"], entry["mac"], ip])
    
    response = app.response_class(
        response=output.getvalue(),
        status=200,
        mimetype='text/csv'
    )
    response.headers["Content-Disposition"] = "attachment; filename=all_switches_port-mac-ip.csv"
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
