import requests
import json
import re

BASE_URL = 'http://127.0.0.1:5000'

def run_exact_demo_verification():
    print("=" * 70)
    print("RUNNING EXACT STAGE 3 DEMO VERIFICATION")
    print("=" * 70)

    s = requests.Session()

    # Step 1: Login
    print("\n[Step 1] Authenticating Operator for Demo...")
    # Register if not already registered
    s.post(f"{BASE_URL}/register", data={
        'username': 'demo_operator',
        'password': 'DemoPassword123!',
        'confirm_password': 'DemoPassword123!'
    })
    r_login = s.post(f"{BASE_URL}/login", data={
        'username': 'demo_operator',
        'password': 'DemoPassword123!'
    }, allow_redirects=False)
    assert r_login.status_code == 302 and '/dashboard' in r_login.headers['Location']
    print("   -> Logged in successfully.")

    # Step 2: Create 'SMVEC Enterprise Network'
    print("\n[Step 2] Creating 'SMVEC Enterprise Network' (192.168.1.0/24, GW: 192.168.1.1)...")
    r_create = s.post(f"{BASE_URL}/networks/create", data={
        'name': 'SMVEC Enterprise Network',
        'network_range': '192.168.1.0/24',
        'gateway': '192.168.1.1'
    }, allow_redirects=True)
    assert r_create.status_code == 200
    assert 'SMVEC Enterprise Network' in r_create.text

    # Extract network ID
    match = re.search(r'/networks/(\d+)/designer', r_create.text)
    if not match:
        match = re.search(r'/networks/(\d+)', r_create.text)
    assert match, "Could not locate network ID on dashboard"
    net_id = match.group(1)
    print(f"   -> 'SMVEC Enterprise Network' created with Network ID: #{net_id}")

    # Step 3: Open Cyber Designer
    print(f"\n[Step 3] Opening Cyber Designer for Network #{net_id}...")
    r_designer = s.get(f"{BASE_URL}/networks/{net_id}/designer")
    assert r_designer.status_code == 200
    assert 'CYBER DESIGNER' in r_designer.text
    assert 'SMVEC Enterprise Network' in r_designer.text
    assert 'cytoscape' in r_designer.text.lower()
    print("   -> Cyber Designer UI loaded with Cytoscape.js canvas and 3-panel workspace.")

    # Step 4: Add the 4 demo devices
    print("\n[Step 4] Adding Demo Devices...")
    devices_to_add = [
        {'name': 'Employee PC', 'device_type': 'Employee PC', 'crit': 'Low', 'x': 100.0, 'y': 150.0},
        {'name': 'Switch', 'device_type': 'Switch', 'crit': 'Medium', 'x': 250.0, 'y': 150.0},
        {'name': 'Application Server', 'device_type': 'Application Server', 'crit': 'High', 'x': 400.0, 'y': 150.0},
        {'name': 'Database Server', 'device_type': 'Database Server', 'crit': 'Critical', 'x': 550.0, 'y': 150.0},
    ]

    dev_map = {}
    for d in devices_to_add:
        r = s.post(f"{BASE_URL}/networks/{net_id}/devices", json={
            'name': d['name'],
            'device_type': d['device_type'],
            'criticality': d['crit'],
            'position_x': d['x'],
            'position_y': d['y']
        })
        assert r.status_code == 201, f"Failed to add {d['name']}: {r.text}"
        dev_data = r.json()
        dev_map[d['name']] = dev_data['id']
        print(f"   -> Added: {dev_data['name']} (ID: #{dev_data['id']}, Type: {dev_data['device_type']}, Criticality: {dev_data['criticality']})")

    # Step 5: Connect devices
    print("\n[Step 5] Connecting Devices...")
    connections_to_create = [
        ('Employee PC', 'Switch'),
        ('Switch', 'Application Server'),
        ('Application Server', 'Database Server')
    ]

    conn_ids = []
    for src_name, tgt_name in connections_to_create:
        src_id = dev_map[src_name]
        tgt_id = dev_map[tgt_name]
        r = s.post(f"{BASE_URL}/networks/{net_id}/connections", json={
            'source_device_id': src_id,
            'target_device_id': tgt_id,
            'connection_type': 'Ethernet'
        })
        assert r.status_code == 201, f"Failed to connect {src_name} -> {tgt_name}: {r.text}"
        conn_data = r.json()
        conn_ids.append(conn_data['id'])
        print(f"   -> Established link #{conn_data['id']}: {src_name} (ID: #{src_id}) -> {tgt_name} (ID: #{tgt_id})")

    # Step 6: Move the nodes around
    print("\n[Step 6] Moving Nodes on Canvas to New Positions...")
    new_positions = {
        str(dev_map['Employee PC']): {'x': 120.0, 'y': 220.0},
        str(dev_map['Switch']): {'x': 280.0, 'y': 220.0},
        str(dev_map['Application Server']): {'x': 440.0, 'y': 220.0},
        str(dev_map['Database Server']): {'x': 600.0, 'y': 220.0}
    }
    for name, cid in dev_map.items():
        coords = new_positions[str(cid)]
        print(f"   -> {name} moved to ({coords['x']}, {coords['y']})")

    # Step 7: Save Topology
    print("\n[Step 7] Saving Topology via API (/topology/save)...")
    r_save = s.post(f"{BASE_URL}/networks/{net_id}/topology/save", json={'positions': new_positions})
    assert r_save.status_code == 200
    assert 'saved successfully' in r_save.text
    print("   -> Topology successfully saved to SQLite backend.")

    # Step 8: Refresh / Reload
    print(f"\n[Step 8] Simulating Page Reload / Fetching /networks/{net_id}/topology...")
    r_reload = s.get(f"{BASE_URL}/networks/{net_id}/topology")
    assert r_reload.status_code == 200
    topo = r_reload.json()
    print("   -> Topology fetched from server on reload.")

    # Step 9: Confirm all four devices and three connections remain
    print("\n[Step 9] Confirming Devices, Connections, and Position Persistence...")
    assert len(topo['devices']) == 4, f"Expected 4 devices, found {len(topo['devices'])}"
    assert len(topo['connections']) == 3, f"Expected 3 connections, found {len(topo['connections'])}"

    reloaded_names = {d['name']: d for d in topo['devices']}
    assert 'Employee PC' in reloaded_names
    assert 'Switch' in reloaded_names
    assert 'Application Server' in reloaded_names
    assert 'Database Server' in reloaded_names

    # Check saved coordinates persisted
    for name in ['Employee PC', 'Switch', 'Application Server', 'Database Server']:
        dev_info = reloaded_names[name]
        expected_pos = new_positions[str(dev_map[name])]
        assert abs(dev_info['position']['x'] - expected_pos['x']) < 0.01
        assert abs(dev_info['position']['y'] - expected_pos['y']) < 0.01
        print(f"   [OK] Device verified: {name} at position ({dev_info['position']['x']}, {dev_info['position']['y']})")

    # Verify connection pairs
    reloaded_pairs = [(c['source_device_id'], c['target_device_id']) for c in topo['connections']]
    assert (dev_map['Employee PC'], dev_map['Switch']) in reloaded_pairs
    assert (dev_map['Switch'], dev_map['Application Server']) in reloaded_pairs
    assert (dev_map['Application Server'], dev_map['Database Server']) in reloaded_pairs
    print(f"   [OK] All 3 connections verified: Employee PC -> Switch -> App Server -> Database Server")

    print("\n" + "=" * 70)
    print("EXACT DEMO VERIFICATION PASSED PERFECTLY!")
    print("=" * 70)

if __name__ == '__main__':
    run_exact_demo_verification()
