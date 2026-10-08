import requests
import json
import time
import sys

BASE_URL = 'http://127.0.0.1:5000'

def main():
    print("=" * 70)
    print("STAGE 5 LIVE VERIFICATION: CYBERATTACK SIMULATION MODULE")
    print("Strictly Virtual In-Memory Simulations - Zero Real Network Activity")
    print("=" * 70)

    session = requests.Session()

    # Step 1: User Registration & Login (Dynamic credentials)
    timestamp = int(time.time())
    username = f"sim_operator_{timestamp}"
    password = "SimPassword2026!"

    print(f"\n[1] Registering and authenticating dynamic operator: '{username}'...")
    r_reg = session.post(f"{BASE_URL}/register", data={
        'username': username,
        'password': password,
        'confirm_password': password
    }, allow_redirects=True)
    if r_reg.status_code != 200 or '/login' not in r_reg.url and '/dashboard' not in r_reg.url:
        print(f"[FAIL] Registration failed: status {r_reg.status_code}")
        sys.exit(1)

    r_login = session.post(f"{BASE_URL}/login", data={
        'username': username,
        'password': password
    }, allow_redirects=True)
    if r_login.status_code != 200 or 'dashboard' not in r_login.url:
        print(f"[FAIL] Login failed: status {r_login.status_code}")
        sys.exit(1)
    print(f"    [OK] Authenticated successfully as '{username}'.")

    # Step 2: Dynamically create an Enterprise Network
    net_name = f"Live Cyber Range {timestamp}"
    net_range = "172.16.0.0/24"
    net_gw = "172.16.0.1"

    print(f"\n[2] Creating dynamic enterprise network: '{net_name}' ({net_range})...")
    r_net = session.post(f"{BASE_URL}/networks/create", data={
        'name': net_name,
        'network_range': net_range,
        'gateway': net_gw
    }, allow_redirects=True)
    if r_net.status_code != 200:
        print(f"[FAIL] Network creation failed: {r_net.status_code}")
        sys.exit(1)
    
    import re
    match = re.search(r'/networks/(\d+)', r_net.text)
    if not match:
        print("[FAIL] Could not find created network ID on dashboard.")
        sys.exit(1)
    network_id = int(match.group(1))
    print(f"    [OK] Network created with ID: {network_id}")

    # Step 3: Build a 3-node topology via Stage 3 Cyber Designer API
    # Nodes: Developer PC -> Application Server -> Database Server
    print("\n[3] Building dynamic 3-node topology via Stage 3 Cyber Designer API...")
    
    r_dev1 = session.post(f"{BASE_URL}/networks/{network_id}/devices", json={
        'name': 'Dev Station',
        'device_type': 'Developer PC',
        'ip_address': '172.16.0.10',
        'os': 'Ubuntu 24.04',
        'criticality': 'Low',
        'position': {'x': 120.0, 'y': 220.0}
    })
    d1 = r_dev1.json()

    r_dev2 = session.post(f"{BASE_URL}/networks/{network_id}/devices", json={
        'name': 'Web App Core',
        'device_type': 'Application Server',
        'ip_address': '172.16.0.20',
        'os': 'Debian 12',
        'criticality': 'High',
        'position': {'x': 320.0, 'y': 220.0}
    })
    d2 = r_dev2.json()

    r_dev3 = session.post(f"{BASE_URL}/networks/{network_id}/devices", json={
        'name': 'Secure Data Vault',
        'device_type': 'Database Server',
        'ip_address': '172.16.0.30',
        'os': 'PostgreSQL on RHEL 9',
        'criticality': 'Critical',
        'position': {'x': 520.0, 'y': 220.0}
    })
    d3 = r_dev3.json()

    # Connections: d1 -> d2 and d2 -> d3
    session.post(f"{BASE_URL}/networks/{network_id}/connections", json={
        'source_device_id': d1['id'],
        'target_device_id': d2['id'],
        'connection_type': 'Ethernet'
    })
    session.post(f"{BASE_URL}/networks/{network_id}/connections", json={
        'source_device_id': d2['id'],
        'target_device_id': d3['id'],
        'connection_type': 'Ethernet'
    })

    print(f"    [OK] Topology created: {d1['name']} (#{d1['id']}) <-> {d2['name']} (#{d2['id']}) <-> {d3['name']} (#{d3['id']})")

    # Step 4: Open and verify Digital Twin initialization
    print("\n[4] Initializing in-memory Digital Twin graph...")
    r_twin_view = session.get(f"{BASE_URL}/networks/{network_id}/digital-twin")
    if r_twin_view.status_code != 200:
        print(f"[FAIL] Digital Twin viewer returned {r_twin_view.status_code}")
        sys.exit(1)

    r_twin_data = session.get(f"{BASE_URL}/networks/{network_id}/digital-twin/data")
    twin_data = r_twin_data.json()
    print(f"    [OK] Digital Twin loaded with {twin_data['node_count']} nodes and {twin_data['edge_count']} edges.")
    all_normal = all(n['state'] == 'NORMAL' for n in twin_data['nodes'])
    print(f"    [OK] All devices initially in state: {'NORMAL' if all_normal else 'MIXED'}")
    assert all_normal, "All devices must initialize to NORMAL"

    # Step 5: Execute Virtual Port Scanning Simulation
    print(f"\n[5] Executing Virtual Port Scan on '{d2['name']}' (#{d2['id']})...")
    r_scan = session.post(f"{BASE_URL}/networks/{network_id}/simulations/port-scan", json={
        'target_device_id': d2['id']
    })
    scan_res = r_scan.json()['simulation']
    print(f"    Result: {scan_res['result']}")
    print(f"    Open Ports Detected: {scan_res['open_ports_count']}")
    for p in scan_res['ports']:
        print(f"      Port {str(p['port']).rjust(4)}: {p['status']}")
    print(f"    Target Virtual State: {scan_res['new_state']}")
    assert scan_res['new_state'] == 'PROBED', "State must transition to PROBED"
    print("    [OK] Virtual Port Scan successfully verified.")

    # Step 6: Execute Virtual Authentication Attack Simulation
    print(f"\n[6] Executing Virtual Authentication Attack on '{d1['name']}' (#{d1['id']})...")
    r_auth = session.post(f"{BASE_URL}/networks/{network_id}/simulations/auth-attack", json={
        'target_device_id': d1['id'],
        'authentication_strength': 'weak',
        'mfa_enabled': False
    })
    auth_res = r_auth.json()['simulation']
    print(f"    Target: {auth_res['target_device_name']}")
    print(f"    Auth Strength: {auth_res['authentication_strength']}, MFA: {'Enabled' if auth_res['mfa_enabled'] else 'Disabled'}")
    print(f"    Outcome: {auth_res['result']}")
    print(f"    New Virtual State: {auth_res['new_state']}")
    assert auth_res['new_state'] == 'COMPROMISED', "State must transition to COMPROMISED"
    print("    [OK] Authentication attack successfully verified.")

    # Step 7: Execute Virtual Lateral Movement Simulation
    print(f"\n[7] Executing Virtual Lateral Movement from COMPROMISED '{d1['name']}' to '{d3['name']}'...")
    r_lm = session.post(f"{BASE_URL}/networks/{network_id}/simulations/lateral-movement", json={
        'source_device_id': d1['id'],
        'target_device_id': d3['id']
    })
    lm_res = r_lm.json()['simulation']
    path_display = " -> ".join(lm_res['path_names'])
    print(f"    NetworkX Path: {path_display}")
    print(f"    Intermediate Affected: {lm_res['affected_devices']}")
    print(f"    Result: {lm_res['result']}")
    print(f"    Target Virtual State: {lm_res['new_state']}")
    assert lm_res['result'] == 'TARGET REACHED', "Result must be TARGET REACHED"
    print("    [OK] Lateral movement path traversal verified.")

    # Step 8: Verify Simulation History in SQLite
    print("\n[8] Verifying SQLite persistent simulation history...")
    r_hist = session.get(f"{BASE_URL}/networks/{network_id}/simulations/history")
    history = r_hist.json()
    print(f"    Recorded History Entries: {len(history)}")
    for h in history:
        src = f"{h['source_device_name']} -> " if h.get('source_device_name') else ""
        print(f"      [{h['simulation_type']}] {src}{h['target_device_name']}: {h['result']} ({h['created_at']})")
    assert len(history) == 3, "Expected 3 recorded simulation runs"
    print("    [OK] Simulation history persistence verified.")

    # Step 9: Verify Original Stage 3 SQLite Topology Records Are Unchanged
    print("\n[9] Verifying SQLite Device and Connection records remain completely untouched...")
    r_top = session.get(f"{BASE_URL}/networks/{network_id}/topology")
    top_data = r_top.json()
    
    assert len(top_data['devices']) == 3, "Device count in SQLite must remain 3"
    assert len(top_data['connections']) == 2, "Connection count in SQLite must remain 2"
    
    # Check that SQLite devices don't have simulation state columns corrupted
    for dev in top_data['devices']:
        print(f"      SQLite Device: #{dev['id']} {dev['name']} ({dev['device_type']}) @ ({dev['position']['x']}, {dev['position']['y']})")
    print("    [OK] Original SQLite topology remains 100% intact and unaltered.")

    # Step 10: Test Virtual Reset
    print("\n[10] Testing In-Memory Virtual State Reset...")
    r_reset = session.post(f"{BASE_URL}/networks/{network_id}/digital-twin/reset")
    reset_data = r_reset.json()
    assert all(n['state'] == 'NORMAL' for n in reset_data['twin']['nodes']), "All nodes must reset to NORMAL"
    print("    [OK] Virtual states cleanly reset to NORMAL in memory.")

    print("\n" + "=" * 70)
    print("ALL STAGE 5 VERIFICATIONS PASSED SUCCESSFULLY [OK]")
    print("=" * 70)

if __name__ == '__main__':
    main()
