# -*- coding: utf-8 -*-
from flask import Flask, render_template, request, jsonify
import subprocess
import re
import json
import time

app = Flask(__name__)
SNMPWALK = "/usr/bin/snmpwalk"

with open('config.json', 'r') as f:
    CONFIG = json.load(f)

SWITCHES = CONFIG['switches']
SETTINGS = CONFIG['settings']

# ARP cache
arp_cache = {}
arp_cache_time = 0

def get_arp_table():
    """Get full ARP table using arp-scan."""
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

def get_switch_data(switch):
    """Get MAC table from switch."""
    ip = switch['ip']
    community = switch['community']
    exclude_ports = switch.get('exclude_ports', [])
    exclude_macs = switch.get('exclude_macs', [])
    
    # 1. Get MAC table
    mac_walk = subprocess.run(
        [SNMPWALK, "-v", "2c", "-c", community, ip, "1.3.6.1.2.1.17.7.1.2.2.1"],
        capture_output=True, text=True, timeout=SETTINGS['snmp_timeout']
    ).stdout.splitlines()

    # 2. Get port names
    port_walk = subprocess.run(
        [SNMPWALK, "-v", "2c", "-c", community, ip, "1.3.6.1.2.1.31.1.1.1.1"],
        capture_output=True, text=True, timeout=SETTINGS['snmp_timeout']
    ).stdout.splitlines()

    port_names = {}
    for line in port_walk:
        m = re.search(r'\.1\.1\.1\.(\d+)\s*=\s*STRING:\s*"(.+?)"', line)
        if m:
            port_names[m.group(1)] = m.group(2)

    # 3. Parse MAC addresses
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

    return all_entries

@app.route('/')
def index():
    return render_template('index.html', switches=SWITCHES)

@app.route('/api/switch/<int:switch_id>')
def get_switch(switch_id):
    if switch_id < 0 or switch_id >= len(SWITCHES):
        return jsonify({"error": "Switch not found"}), 404

    switch = SWITCHES[switch_id]
    entries = get_switch_data(switch)
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

@app.route('/api/search')
def search():
    query = request.args.get('q', '').strip().upper()
    if not query:
        return jsonify({"error": "Enter search query"}), 400

    results = []
    for switch in SWITCHES:
        entries = get_switch_data(switch)
        arp = get_arp_table()
        
        for entry in entries:
            ip = arp.get(entry["mac_raw"], "Not found")
            if query in entry["mac"] or query in ip:
                results.append({
                    "switch": switch['name'],
                    "port": entry["port"],
                    "mac": entry["mac"],
                    "ip": ip
                })

    return jsonify({"results": results, "count": len(results)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
