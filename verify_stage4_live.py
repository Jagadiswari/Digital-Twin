import requests
import json
import re

BASE_URL = 'http://127.0.0.1:5000'

def run_stage4_verification():
    print("=" * 70)
    print("STARTING STAGE 4 LIVE VERIFICATION: DIGITAL TWIN BUILDER & VIEWER")
    print("=" * 70)

    s1 = requests.Session()
    s2 = requests.Session()

    # Step 1: Login primary user
    print("\n[1/10] Authenticating Operator One (Owner)...")
    s1.post(f"{BASE_URL}/register", data={
        'username': 'twin_live_owner',
        'password': 'TwinPassword123!',
        'confirm_password': 'TwinPassword123!'
    })
    r_login1 = s1.post(f"{BASE_URL}/login", data={
        'username': 'twin_live_owner',
        'password': 'TwinPassword123!'
    }, allow_redirects=False)
    assert r_login1.status_code == 302
    print("   [OK] Operator One authenticated.")

    # Step 2: Login secondary user (for ownership tests)
    print("\n[2/10] Authenticating Operator Two (Unauthorized User)...")
    s2.post(f"{BASE_URL}/register", data={
        'username': 'twin_live_attacker',
        'password': 'AttackerPassword123!',
        'confirm_password': 'AttackerPassword123!'
    })
    r_login2 = s2.post(f"{BASE_URL}/login", data={
        'username': 'twin_live_attacker',
        'password': 'AttackerPassword123!'
    }, allow_redirects=False)
    assert r_login2.status_code == 302
    print("   [OK] Operator Two authenticated.")

    # Step 3: Create Enterprise Network
    print("\n[3/10] Establishing Enterprise Network 'SMVEC Enterprise Network'...")
    r_net = s1.post(f"{BASE_URL}/networks/create", data={
        'name': 'SMVEC Enterprise Network',
        'network_range': '192.168.1.0/24',
        'gateway': '192.168.1.1'
    }, allow_redirects=True)
    assert r_net.status_code == 200

    match = re.search(r'/networks/(\d+)/digital-twin', r_net.text)
    if not match:
        match = re.search(r'/networks/(\d+)', r_net.text)
    assert match, "Could not find network ID on dashboard"
    net_id = match.group(1)
    print(f"   [OK] Network created with ID: #{net_id}")

    # Step 4: Populate Stage 3 Topology (4 devices, 3 connections)
    print("\n[4/10] Populating Stage 3 Topology (Employee PC -> Switch -> App Server -> DB Server)...")
    devices = [
        {'name': 'Employee PC', 'type': 'Employee PC', 'crit': 'Low', 'x': 100.0, 'y': 150.0},
        {'name': 'Switch', 'type': 'Switch', 'crit': 'Medium', 'x': 250.0, 'y': 150.0},
        {'name': 'Application Server', 'type': 'Application Server', 'crit': 'High', 'x': 400.0, 'y': 150.0},
        {'name': 'Database Server', 'type': 'Database Server', 'crit': 'Critical', 'x': 550.0, 'y': 150.0},
    ]

    dev_map = {}
    for d in devices:
        r = s1.post(f"{BASE_URL}/networks/{net_id}/devices", json={
            'name': d['name'],
            'device_type': d['type'],
            'criticality': d['crit'],
            'position_x': d['x'],
            'position_y': d['y']
        })
        assert r.status_code == 201
        dev_map[d['name']] = r.json()['id']

    # Establish connections
    links = [
        ('Employee PC', 'Switch'),
        ('Switch', 'Application Server'),
        ('Application Server', 'Database Server')
    ]
    for src, tgt in links:
        r = s1.post(f"{BASE_URL}/networks/{net_id}/connections", json={
            'source_device_id': dev_map[src],
            'target_device_id': dev_map[tgt]
        })
        assert r.status_code == 201

    print("   [OK] 4 devices and 3 connections successfully established in Stage 3.")

    # Step 5: Open Digital Twin Viewer
    print(f"\n[5/10] Opening Digital Twin Viewer for Network #{net_id}...")
    r_viewer = s1.get(f"{BASE_URL}/networks/{net_id}/digital-twin")
    assert r_viewer.status_code == 200
    assert 'DIGITAL TWIN' in r_viewer.text
    assert 'NetworkX In-Memory' in r_viewer.text
    assert 'SMVEC Enterprise Network' in r_viewer.text
    assert 'cyTwin' in r_viewer.text
    assert 'VIRTUAL DEVICE INSPECTOR' in r_viewer.text
    print("   [OK] Digital Twin viewer rendered with Cytoscape container and Inspector.")

    # Step 6: Fetch Digital Twin API Data (/digital-twin/data)
    print(f"\n[6/10] Fetching Digital Twin Data (/networks/{net_id}/digital-twin/data)...")
    r_data = s1.get(f"{BASE_URL}/networks/{net_id}/digital-twin/data")
    assert r_data.status_code == 200
    data = r_data.json()

    assert data['network_id'] == int(net_id)
    assert data['network_name'] == 'SMVEC Enterprise Network'
    assert data['node_count'] == 4, f"Expected 4 nodes, got {data['node_count']}"
    assert data['edge_count'] == 3, f"Expected 3 edges, got {data['edge_count']}"
    print("   [OK] Digital Twin data returned 4 nodes and 3 edges from in-memory NetworkX.")

    # Step 7: Confirm All Virtual Device States are NORMAL
    print("\n[7/10] Validating that every virtual device has state 'NORMAL'...")
    for node in data['nodes']:
        assert node['state'] == 'NORMAL', f"Device {node['name']} state is {node['state']}, expected NORMAL"
        print(f"   [OK] Device #{node['id']} ({node['name']}, Type: {node['device_type']}) -> State: {node['state']}")

    # Step 8: Verify Connections in Virtual Twin
    print("\n[8/10] Verifying connections in Digital Twin...")
    edge_pairs = [(e['source'], e['target']) for e in data['edges']]
    assert (dev_map['Employee PC'], dev_map['Switch']) in edge_pairs or (dev_map['Switch'], dev_map['Employee PC']) in edge_pairs
    assert (dev_map['Switch'], dev_map['Application Server']) in edge_pairs or (dev_map['Application Server'], dev_map['Switch']) in edge_pairs
    assert (dev_map['Application Server'], dev_map['Database Server']) in edge_pairs or (dev_map['Database Server'], dev_map['Application Server']) in edge_pairs
    print("   [OK] Virtual links match Stage 3 topology: Employee PC - Switch - App Server - DB Server.")

    # Step 9: Verify Ownership Protection
    print("\n[9/10] Testing Ownership Security (User 2 blocked from User 1's Digital Twin)...")
    r_unauth_viewer = s2.get(f"{BASE_URL}/networks/{net_id}/digital-twin")
    assert r_unauth_viewer.status_code == 403
    r_unauth_data = s2.get(f"{BASE_URL}/networks/{net_id}/digital-twin/data")
    assert r_unauth_data.status_code == 403

    unauth_sess = requests.Session()
    r_anon = unauth_sess.get(f"{BASE_URL}/networks/{net_id}/digital-twin", allow_redirects=False)
    assert r_anon.status_code == 302 and '/login' in r_anon.headers['Location']
    print("   [OK] Ownership protection enforced: 403 Forbidden for unauthorized user, 302 for unauthenticated.")

    # Step 10: Verify Stage 3 Designer Still Functions Unaltered
    print("\n[10/10] Verifying Stage 3 Cyber Designer remains operational...")
    r_designer = s1.get(f"{BASE_URL}/networks/{net_id}/designer")
    assert r_designer.status_code == 200
    r_topo = s1.get(f"{BASE_URL}/networks/{net_id}/topology")
    assert r_topo.status_code == 200
    topo = r_topo.json()
    assert len(topo['devices']) == 4
    assert len(topo['connections']) == 3
    print("   [OK] Stage 3 Cyber Designer and topology APIs remain completely functional.")

    print("\n" + "=" * 70)
    print("ALL 10 STAGE 4 LIVE VERIFICATION CHECKS PASSED SUCCESSFULLY!")
    print("=" * 70)

if __name__ == '__main__':
    run_stage4_verification()
