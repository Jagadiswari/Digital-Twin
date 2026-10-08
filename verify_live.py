import requests
import sys

BASE_URL = 'http://127.0.0.1:5000'

def run_verification():
    session = requests.Session()
    print("[1/9] Testing root URL redirect...")
    r = session.get(f"{BASE_URL}/", allow_redirects=False)
    assert r.status_code == 302 and '/login' in r.headers['Location'], f"Failed root redirect: {r.status_code}"
    print("   -> Root correctly redirects to /login")

    print("[2/9] Testing login page GET...")
    r = session.get(f"{BASE_URL}/login")
    assert r.status_code == 200 and 'OPERATOR AUTHENTICATION' in r.text
    print("   -> Login page loaded successfully")

    import time
    test_user = f"cyber_admin_{int(time.time())}"
    print(f"[3/9] Testing user registration ({test_user})...")
    reg_data = {
        'username': test_user,
        'password': 'ComplexPassword!2026',
        'confirm_password': 'ComplexPassword!2026'
    }
    r = session.post(f"{BASE_URL}/register", data=reg_data, allow_redirects=False)
    assert r.status_code == 302 and '/login' in r.headers['Location']
    print("   -> Registration successful, redirected to /login")

    print("[4/9] Testing duplicate user registration prevention...")
    r = session.post(f"{BASE_URL}/register", data=reg_data)
    assert r.status_code == 409 and 'already taken' in r.text
    print("   -> Duplicate registration properly blocked with 409")

    print("[5/9] Testing protected dashboard without authentication...")
    unauth_session = requests.Session()
    r = unauth_session.get(f"{BASE_URL}/dashboard", allow_redirects=False)
    assert r.status_code == 302 and '/login' in r.headers['Location']
    print("   -> Unauthenticated access to /dashboard properly blocked and redirected")

    print("[6/9] Testing login with invalid password...")
    r = unauth_session.post(f"{BASE_URL}/login", data={
        'username': 'cyber_admin',
        'password': 'WrongPassword123'
    })
    assert r.status_code == 401 and 'Invalid username or password' in r.text
    print("   -> Invalid login rejected with 401")

    print("[7/9] Testing login with valid credentials...")
    r = unauth_session.post(f"{BASE_URL}/login", data=reg_data, allow_redirects=False)
    assert r.status_code == 302 and '/dashboard' in r.headers['Location']
    print("   -> Login succeeded, redirected to /dashboard")

    print("[8/9] Testing authenticated dashboard access...")
    r = unauth_session.get(f"{BASE_URL}/dashboard")
    assert r.status_code == 200 and 'Welcome to Cyber-Twin Portal' in r.text and 'cyber_admin' in r.text
    print("   -> Dashboard accessible and rendered operator welcome view")

    print("[9/9] Testing session logout & subsequent dashboard lock...")
    r = unauth_session.get(f"{BASE_URL}/logout", allow_redirects=False)
    assert r.status_code == 302 and '/login' in r.headers['Location']
    r_post_logout = unauth_session.get(f"{BASE_URL}/dashboard", allow_redirects=False)
    assert r_post_logout.status_code == 302 and '/login' in r_post_logout.headers['Location']
    print("   -> Logout succeeded and session invalidated")

    print("\n>>> ALL LIVE VERIFICATION CHECKS PASSED SUCCESSFULLY! <<<")

if __name__ == '__main__':
    run_verification()
