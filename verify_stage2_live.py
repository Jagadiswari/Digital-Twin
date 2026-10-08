import requests
import sys

BASE_URL = 'http://127.0.0.1:5000'

def run_stage2_verification():
    print("=" * 60)
    print("STARTING STAGE 2 LIVE INTEGRATION VERIFICATION")
    print("=" * 60)

    # Session for User 1
    s1 = requests.Session()
    # Session for User 2
    s2 = requests.Session()

    # Step 1: Register and login User 1
    print("\n[1/12] Registering & Authenticating Operator One...")
    s1.post(f"{BASE_URL}/register", data={
        'username': 'operator_live_one',
        'password': 'LivePassword123!',
        'confirm_password': 'LivePassword123!'
    })
    r = s1.post(f"{BASE_URL}/login", data={
        'username': 'operator_live_one',
        'password': 'LivePassword123!'
    }, allow_redirects=False)
    assert r.status_code == 302 and '/dashboard' in r.headers['Location']
    print("   -> Operator One successfully logged in.")

    # Step 2: Register and login User 2
    print("\n[2/12] Registering & Authenticating Operator Two...")
    s2.post(f"{BASE_URL}/register", data={
        'username': 'operator_live_two',
        'password': 'LivePassword456!',
        'confirm_password': 'LivePassword456!'
    })
    r = s2.post(f"{BASE_URL}/login", data={
        'username': 'operator_live_two',
        'password': 'LivePassword456!'
    }, allow_redirects=False)
    assert r.status_code == 302 and '/dashboard' in r.headers['Location']
    print("   -> Operator Two successfully logged in.")

    # Step 3: Test IPv4 Network Validation Failures
    print("\n[3/12] Testing Invalid Network Range Validation...")
    r = s1.post(f"{BASE_URL}/networks/create", data={
        'name': 'Bad CIDR Net',
        'network_range': '999.1.1.0/24',
        'gateway': '192.168.1.1'
    })
    assert r.status_code == 400 and 'Invalid IPv4 network range' in r.text
    print("   -> Invalid network range rejected with 400.")

    print("\n[4/12] Testing Invalid Gateway Validation...")
    r = s1.post(f"{BASE_URL}/networks/create", data={
        'name': 'Bad Gateway Net',
        'network_range': '192.168.1.0/24',
        'gateway': '192.168.1.999'
    })
    assert r.status_code == 400 and 'Invalid IPv4 gateway address' in r.text
    print("   -> Invalid gateway IP rejected with 400.")

    print("\n[5/12] Testing Gateway Outside Network Range Validation...")
    r = s1.post(f"{BASE_URL}/networks/create", data={
        'name': 'Mismatch Gateway Net',
        'network_range': '192.168.1.0/24',
        'gateway': '10.0.0.1'
    })
    assert r.status_code == 400 and 'does not belong to network range' in r.text
    print("   -> Gateway outside network rejected with 400.")

    # Step 6: Create Valid Network for User 1
    print("\n[6/12] Creating Valid Enterprise Network for Operator One (SMVEC Enterprise Network)...")
    r = s1.post(f"{BASE_URL}/networks/create", data={
        'name': 'SMVEC Enterprise Network',
        'network_range': '192.168.1.0/24',
        'gateway': '192.168.1.1'
    }, allow_redirects=True)
    assert r.status_code == 200 and 'SMVEC Enterprise Network' in r.text
    print("   -> 'SMVEC Enterprise Network' successfully created and listed on Dashboard.")

    # Retrieve created network ID from Operator 1's dashboard
    import re
    match = re.search(r'/networks/(\d+)', r.text)
    assert match, "Could not find created network ID on dashboard"
    net_id = match.group(1)
    print(f"   -> Created Network ID: #{net_id}")

    # Step 7: Open Network Detail View
    print(f"\n[7/12] Operator One Opening Network #{net_id}...")
    r = s1.get(f"{BASE_URL}/networks/{net_id}")
    assert r.status_code == 200
    assert 'SMVEC Enterprise Network' in r.text
    assert '192.168.1.0/24' in r.text
    assert '192.168.1.1' in r.text
    assert '255.255.255.0' in r.text  # computed netmask
    assert '192.168.1.255' in r.text  # computed broadcast
    print("   -> Network details and computed IP metrics verified.")

    # Step 8: Ownership Protection Checks (User 2 attempting to access User 1's network)
    print(f"\n[8/12] Security Test: Operator Two attempting unauthorized access to Network #{net_id}...")
    # View attempt
    r_view = s2.get(f"{BASE_URL}/networks/{net_id}")
    assert r_view.status_code == 403
    print("   -> Unauthorized view attempt blocked (403 Forbidden).")

    # Edit attempt
    r_edit = s2.post(f"{BASE_URL}/networks/{net_id}/edit", data={
        'name': 'Attacker Network Hijack',
        'network_range': '192.168.1.0/24',
        'gateway': '192.168.1.1'
    })
    assert r_edit.status_code == 403
    print("   -> Unauthorized edit attempt blocked (403 Forbidden).")

    # Delete attempt
    r_del = s2.post(f"{BASE_URL}/networks/{net_id}/delete")
    assert r_del.status_code == 403
    print("   -> Unauthorized deletion attempt blocked (403 Forbidden).")

    # Step 9: User 2 Dashboard Isolation
    print("\n[9/12] Verifying Operator Two Dashboard Isolation...")
    r_dash_u2 = s2.get(f"{BASE_URL}/dashboard")
    assert 'SMVEC Enterprise Network' not in r_dash_u2.text
    assert 'No Enterprise Networks Configured' in r_dash_u2.text
    print("   -> Operator Two cannot see Operator One's network.")

    # Step 10: User 1 Edits Network
    print(f"\n[10/12] Operator One Editing Network #{net_id}...")
    r_edit_ok = s1.post(f"{BASE_URL}/networks/{net_id}/edit", data={
        'name': 'SMVEC Enterprise Core V2',
        'network_range': '172.16.0.0/20',
        'gateway': '172.16.0.1'
    }, allow_redirects=True)
    assert r_edit_ok.status_code == 200
    assert 'SMVEC Enterprise Core V2' in r_edit_ok.text
    assert '172.16.0.0/20' in r_edit_ok.text
    assert '172.16.0.1' in r_edit_ok.text
    print("   -> Network edit successfully committed and re-rendered.")

    # Step 11: User 1 Deletes Network
    print(f"\n[11/12] Operator One Decommissioning (Deleting) Network #{net_id}...")
    r_del_ok = s1.post(f"{BASE_URL}/networks/{net_id}/delete", allow_redirects=True)
    assert r_del_ok.status_code == 200
    assert 'was decommissioned and removed' in r_del_ok.text
    assert 'No Enterprise Networks Configured' in r_del_ok.text
    print("   -> Network successfully deleted and removed from dashboard.")

    # Step 12: Verify Network is Deleted
    print(f"\n[12/12] Verifying Network #{net_id} no longer exists...")
    r_check = s1.get(f"{BASE_URL}/networks/{net_id}")
    assert r_check.status_code == 404
    print("   -> Accessing deleted network returns 404 Not Found.")

    print("\n" + "=" * 60)
    print("ALL 12 STAGE 2 LIVE VERIFICATION CHECKS PASSED!")
    print("=" * 60)

if __name__ == '__main__':
    run_stage2_verification()
