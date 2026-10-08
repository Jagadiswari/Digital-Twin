import unittest
import networkx as nx
from config import TestConfig
from app import create_app
from models import db, User, Network, Device, Connection, SimulationHistory
from digital_twin import DigitalTwinBuilder, TWIN_STATES, DEFAULT_INITIAL_STATE, PREDEFINED_PORTS, twin_instances

class Stage1AuthTestCase(unittest.TestCase):
    def setUp(self):
        """Set up test application and in-memory test database."""
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

    def tearDown(self):
        """Tear down test database and app context."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_database_creation(self):
        """Test 1: Verify database and user table schema creation."""
        inspector = db.inspect(db.engine)
        tables = inspector.get_table_names()
        self.assertIn('users', tables)
        self.assertIn('networks', tables)

        columns = [col['name'] for col in inspector.get_columns('users')]
        self.assertIn('id', columns)
        self.assertIn('username', columns)
        self.assertIn('password_hash', columns)
        self.assertIn('created_at', columns)

    def test_registration(self):
        """Test 2: Verify user registration and duplicate username prevention."""
        response = self.client.post('/register', data={
            'username': 'operator_alpha',
            'password': 'SecurePassword123!',
            'confirm_password': 'SecurePassword123!'
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/login'))

        user = User.query.filter_by(username='operator_alpha').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.username, 'operator_alpha')

        # Test duplicate username rejection
        dup_response = self.client.post('/register', data={
            'username': 'operator_alpha',
            'password': 'AnotherPassword123!',
            'confirm_password': 'AnotherPassword123!'
        }, follow_redirects=True)
        self.assertEqual(dup_response.status_code, 409)
        self.assertIn(b'already taken', dup_response.data)

        # Test password mismatch rejection
        mismatch_response = self.client.post('/register', data={
            'username': 'operator_beta',
            'password': 'PasswordA',
            'confirm_password': 'PasswordB'
        }, follow_redirects=True)
        self.assertEqual(mismatch_response.status_code, 400)
        self.assertIn(b'Passwords do not match', mismatch_response.data)

    def test_password_hashing(self):
        """Test 3: Verify password is saved as Werkzeug hash and never plaintext."""
        raw_password = 'SuperSecretCyberKey2026'
        user = User(username='crypto_analyst')
        user.set_password(raw_password)
        db.session.add(user)
        db.session.commit()

        queried = User.query.filter_by(username='crypto_analyst').first()
        self.assertIsNotNone(queried)
        self.assertNotEqual(queried.password_hash, raw_password)
        self.assertTrue(
            queried.password_hash.startswith('scrypt:') or queried.password_hash.startswith('pbkdf2:'),
            f"Expected Werkzeug hash prefix, got {queried.password_hash[:15]}"
        )
        self.assertTrue(queried.check_password(raw_password))
        self.assertFalse(queried.check_password('WrongPassword'))

    def test_successful_login(self):
        """Test 4: Verify successful login sets session and redirects to dashboard."""
        user = User(username='authorized_operator')
        user.set_password('CorrectPassword123')
        db.session.add(user)
        db.session.commit()

        response = self.client.post('/login', data={
            'username': 'authorized_operator',
            'password': 'CorrectPassword123'
        }, follow_redirects=False)

        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/dashboard'))

        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get('user_id'), user.id)
            self.assertEqual(sess.get('username'), 'authorized_operator')

    def test_failed_login(self):
        """Test 5: Verify failed login with wrong credentials rejects access."""
        user = User(username='existing_operator')
        user.set_password('CorrectPassword123')
        db.session.add(user)
        db.session.commit()

        # Case A: Wrong password
        response_wrong_pw = self.client.post('/login', data={
            'username': 'existing_operator',
            'password': 'WrongPassword999'
        }, follow_redirects=True)
        self.assertEqual(response_wrong_pw.status_code, 401)
        self.assertIn(b'Invalid username or password', response_wrong_pw.data)

        # Case B: Non-existent username
        response_wrong_user = self.client.post('/login', data={
            'username': 'ghost_operator',
            'password': 'AnyPassword'
        }, follow_redirects=True)
        self.assertEqual(response_wrong_user.status_code, 401)
        self.assertIn(b'Invalid username or password', response_wrong_user.data)

        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get('user_id'))

    def test_protected_dashboard(self):
        """Test 6: Verify unauthenticated users are redirected, authenticated see welcome page."""
        unauth_response = self.client.get('/dashboard', follow_redirects=False)
        self.assertEqual(unauth_response.status_code, 302)
        self.assertTrue(unauth_response.headers['Location'].endswith('/login'))

        user = User(username='twin_admin')
        user.set_password('AdminKey2026')
        db.session.add(user)
        db.session.commit()

        with self.client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['username'] = user.username

        auth_response = self.client.get('/dashboard', follow_redirects=True)
        self.assertEqual(auth_response.status_code, 200)
        self.assertIn(b'Welcome to Cyber-Twin Portal', auth_response.data)
        self.assertIn(b'twin_admin', auth_response.data)
        self.assertIn(b'SESSION AUTHENTICATED', auth_response.data)

    def test_logout(self):
        """Test 7: Verify logout clears session and redirects to login."""
        user = User(username='session_user')
        user.set_password('Pass123456')
        db.session.add(user)
        db.session.commit()

        with self.client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['username'] = user.username

        logout_response = self.client.get('/logout', follow_redirects=False)
        self.assertEqual(logout_response.status_code, 302)
        self.assertTrue(logout_response.headers['Location'].endswith('/login'))

        with self.client.session_transaction() as sess:
            self.assertIsNone(sess.get('user_id'))
            self.assertIsNone(sess.get('username'))

        post_logout_response = self.client.get('/dashboard', follow_redirects=False)
        self.assertEqual(post_logout_response.status_code, 302)
        self.assertTrue(post_logout_response.headers['Location'].endswith('/login'))


class Stage2NetworkTestCase(unittest.TestCase):
    def setUp(self):
        """Set up test application, in-memory database, and test users."""
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Seed User 1 (Primary Operator)
        self.user1 = User(username='operator_one')
        self.user1.set_password('Password123!')
        db.session.add(self.user1)

        # Seed User 2 (Secondary Operator)
        self.user2 = User(username='operator_two')
        self.user2.set_password('Password456!')
        db.session.add(self.user2)
        db.session.commit()

    def tearDown(self):
        """Tear down test database and app context."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _login(self, user):
        """Helper to simulate authenticated session for a user."""
        with self.client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['username'] = user.username

    def test_network_creation(self):
        """Stage 2 Test 1: Verify enterprise network creation and database fields."""
        self._login(self.user1)

        response = self.client.post('/networks/create', data={
            'name': 'SMVEC Enterprise Network',
            'network_range': '192.168.1.0/24',
            'gateway': '192.168.1.1'
        }, follow_redirects=False)

        # Should redirect to dashboard on success
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/dashboard'))

        # Verify network stored in database with proper fields
        network = Network.query.filter_by(name='SMVEC Enterprise Network').first()
        self.assertIsNotNone(network)
        self.assertEqual(network.user_id, self.user1.id)
        self.assertEqual(network.network_range, '192.168.1.0/24')
        self.assertEqual(network.gateway, '192.168.1.1')
        self.assertIsNotNone(network.created_at)
        self.assertIsNotNone(network.updated_at)

    def test_network_listing(self):
        """Stage 2 Test 2: Verify user only sees their own networks on the dashboard."""
        # Create 2 networks for User 1
        net1_user1 = Network(user_id=self.user1.id, name='User1 Corp Net', network_range='10.0.0.0/24', gateway='10.0.0.1')
        net2_user1 = Network(user_id=self.user1.id, name='User1 DMZ', network_range='172.16.0.0/24', gateway='172.16.0.1')
        # Create 1 network for User 2
        net1_user2 = Network(user_id=self.user2.id, name='User2 Private Lab', network_range='192.168.50.0/24', gateway='192.168.50.1')
        db.session.add_all([net1_user1, net2_user1, net1_user2])
        db.session.commit()

        # Log in as User 1
        self._login(self.user1)
        res_u1 = self.client.get('/dashboard')
        self.assertEqual(res_u1.status_code, 200)
        self.assertIn(b'User1 Corp Net', res_u1.data)
        self.assertIn(b'User1 DMZ', res_u1.data)
        self.assertNotIn(b'User2 Private Lab', res_u1.data)

        # Log in as User 2
        self._login(self.user2)
        res_u2 = self.client.get('/dashboard')
        self.assertEqual(res_u2.status_code, 200)
        self.assertIn(b'User2 Private Lab', res_u2.data)
        self.assertNotIn(b'User1 Corp Net', res_u2.data)
        self.assertNotIn(b'User1 DMZ', res_u2.data)

    def test_network_editing(self):
        """Stage 2 Test 3: Verify editing network name, range, and gateway."""
        net = Network(user_id=self.user1.id, name='Initial Net', network_range='192.168.1.0/24', gateway='192.168.1.1')
        db.session.add(net)
        db.session.commit()

        self._login(self.user1)

        # GET edit form
        get_res = self.client.get(f'/networks/{net.id}/edit')
        self.assertEqual(get_res.status_code, 200)
        self.assertIn(b'Initial Net', get_res.data)

        # POST updated values
        post_res = self.client.post(f'/networks/{net.id}/edit', data={
            'name': 'SMVEC Enterprise Network Updated',
            'network_range': '10.10.0.0/16',
            'gateway': '10.10.0.254'
        }, follow_redirects=False)

        self.assertEqual(post_res.status_code, 302)

        # Reload from database and verify updates
        updated_net = db.session.get(Network, net.id)
        self.assertEqual(updated_net.name, 'SMVEC Enterprise Network Updated')
        self.assertEqual(updated_net.network_range, '10.10.0.0/16')
        self.assertEqual(updated_net.gateway, '10.10.0.254')

    def test_network_deletion(self):
        """Stage 2 Test 4: Verify network deletion."""
        net = Network(user_id=self.user1.id, name='Network To Delete', network_range='192.168.1.0/24', gateway='192.168.1.1')
        db.session.add(net)
        db.session.commit()
        net_id = net.id

        self._login(self.user1)

        # Delete network
        response = self.client.post(f'/networks/{net_id}/delete', follow_redirects=False)
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].endswith('/dashboard'))

        # Verify network is removed from database
        deleted_net = db.session.get(Network, net_id)
        self.assertIsNone(deleted_net)

    def test_authentication_protection(self):
        """Stage 2 Test 5: Verify all network routes redirect unauthenticated users to /login."""
        net = Network(user_id=self.user1.id, name='Secured Net', network_range='192.168.1.0/24', gateway='192.168.1.1')
        db.session.add(net)
        db.session.commit()

        # Without login:
        endpoints = [
            ('GET', '/networks/create'),
            ('POST', '/networks/create'),
            ('GET', f'/networks/{net.id}'),
            ('GET', f'/networks/{net.id}/edit'),
            ('POST', f'/networks/{net.id}/edit'),
            ('POST', f'/networks/{net.id}/delete'),
        ]

        for method, url in endpoints:
            if method == 'GET':
                res = self.client.get(url, follow_redirects=False)
            else:
                res = self.client.post(url, follow_redirects=False)
            self.assertEqual(res.status_code, 302, f"Failed for {method} {url}")
            self.assertTrue(res.headers['Location'].endswith('/login'), f"Redirect target wrong for {method} {url}")

    def test_ownership_protection(self):
        """Stage 2 Test 6: Verify User 2 cannot view, edit, or delete User 1's network."""
        net = Network(user_id=self.user1.id, name='User1 Private Network', network_range='192.168.1.0/24', gateway='192.168.1.1')
        db.session.add(net)
        db.session.commit()
        net_id = net.id

        # Log in as User 2
        self._login(self.user2)

        # Attempt to view User 1's network -> 403 Forbidden
        view_res = self.client.get(f'/networks/{net_id}')
        self.assertEqual(view_res.status_code, 403)

        # Attempt to get edit form for User 1's network -> 403 Forbidden
        edit_get_res = self.client.get(f'/networks/{net_id}/edit')
        self.assertEqual(edit_get_res.status_code, 403)

        # Attempt to post edit to User 1's network -> 403 Forbidden
        edit_post_res = self.client.post(f'/networks/{net_id}/edit', data={
            'name': 'Hacked Network Name',
            'network_range': '192.168.1.0/24',
            'gateway': '192.168.1.1'
        })
        self.assertEqual(edit_post_res.status_code, 403)

        # Attempt to delete User 1's network -> 403 Forbidden
        delete_res = self.client.post(f'/networks/{net_id}/delete')
        self.assertEqual(delete_res.status_code, 403)

        # Verify network remains intact in database
        check_net = db.session.get(Network, net_id)
        self.assertIsNotNone(check_net)
        self.assertEqual(check_net.name, 'User1 Private Network')

    def test_invalid_network_range(self):
        """Stage 2 Test 7: Verify invalid network range (malformed CIDR or host bits set) is rejected."""
        self._login(self.user1)

        # Case A: Totally invalid CIDR
        res1 = self.client.post('/networks/create', data={
            'name': 'Bad Range Net',
            'network_range': '999.999.1.0/24',
            'gateway': '192.168.1.1'
        }, follow_redirects=True)
        self.assertEqual(res1.status_code, 400)
        self.assertIn(b'Invalid IPv4 network range', res1.data)

        # Case B: CIDR with host bits set in strict mode (e.g. 192.168.1.5/24)
        res2 = self.client.post('/networks/create', data={
            'name': 'Host Bits Set Net',
            'network_range': '192.168.1.5/24',
            'gateway': '192.168.1.1'
        }, follow_redirects=True)
        self.assertEqual(res2.status_code, 400)
        self.assertIn(b'Invalid IPv4 network range', res2.data)

        # Verify no network was created
        self.assertEqual(Network.query.count(), 0)

    def test_invalid_gateway(self):
        """Stage 2 Test 8: Verify malformed gateway IP is rejected."""
        self._login(self.user1)

        res = self.client.post('/networks/create', data={
            'name': 'Bad Gateway Net',
            'network_range': '192.168.1.0/24',
            'gateway': '192.168.1.999'
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 400)
        self.assertIn(b'Invalid IPv4 gateway address', res.data)
        self.assertEqual(Network.query.count(), 0)

    def test_gateway_outside_network(self):
        """Stage 2 Test 9: Verify gateway outside network range is rejected."""
        self._login(self.user1)

        # Gateway 10.0.0.1 is not in 192.168.1.0/24
        res = self.client.post('/networks/create', data={
            'name': 'Mismatched Gateway Net',
            'network_range': '192.168.1.0/24',
            'gateway': '10.0.0.1'
        }, follow_redirects=True)

        self.assertEqual(res.status_code, 400)
        self.assertIn(b'does not belong to network range', res.data)
        self.assertEqual(Network.query.count(), 0)


class Stage3DesignerTestCase(unittest.TestCase):
    def setUp(self):
        """Set up test application, in-memory database, test users, and primary test network."""
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Seed User 1 (Owner)
        self.user1 = User(username='sec_admin')
        self.user1.set_password('AdminPass123!')
        db.session.add(self.user1)

        # Seed User 2 (Attacker / Unauthorized)
        self.user2 = User(username='rogue_operator')
        self.user2.set_password('RoguePass456!')
        db.session.add(self.user2)
        db.session.commit()

        # Seed Network for User 1
        self.network1 = Network(
            user_id=self.user1.id,
            name='SMVEC Enterprise Network',
            network_range='192.168.1.0/24',
            gateway='192.168.1.1'
        )
        db.session.add(self.network1)
        db.session.commit()

    def tearDown(self):
        """Tear down database and app context."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _login(self, user):
        """Simulate session authentication."""
        with self.client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['username'] = user.username

    def test_device_creation(self):
        """Stage 3 Test 1: Verify device creation from template."""
        self._login(self.user1)

        res = self.client.post(f'/networks/{self.network1.id}/devices', json={
            'name': 'Employee PC 1',
            'device_type': 'Employee PC',
            'criticality': 'Low',
            'position_x': 100.0,
            'position_y': 200.0
        })

        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data['name'], 'Employee PC 1')
        self.assertEqual(data['device_type'], 'Employee PC')
        self.assertEqual(data['criticality'], 'Low')
        self.assertEqual(data['position']['x'], 100.0)
        self.assertEqual(data['position']['y'], 200.0)

        # Verify device saved in SQLite database
        device = db.session.get(Device, data['id'])
        self.assertIsNotNone(device)
        self.assertEqual(device.network_id, self.network1.id)

    def test_maximum_5_devices(self):
        """Stage 3 Test 2: Verify maximum 5 devices limit with specific warning message."""
        self._login(self.user1)

        # Add 5 devices
        for i in range(1, 6):
            res = self.client.post(f'/networks/{self.network1.id}/devices', json={
                'name': f'Device {i}',
                'device_type': 'Switch'
            })
            self.assertEqual(res.status_code, 201)

        self.assertEqual(Device.query.filter_by(network_id=self.network1.id).count(), 5)

        # Attempt to add a 6th device
        res6 = self.client.post(f'/networks/{self.network1.id}/devices', json={
            'name': 'Device 6 (Overflow)',
            'device_type': 'Firewall'
        })

        self.assertEqual(res6.status_code, 400)
        data6 = res6.get_json()
        self.assertIn('Maximum 5 devices allowed for this demo.', data6.get('error', ''))

        # Count in database must remain 5
        self.assertEqual(Device.query.filter_by(network_id=self.network1.id).count(), 5)

    def test_device_update(self):
        """Stage 3 Test 3: Verify device renaming, IP/OS, and criticality updates."""
        self._login(self.user1)

        dev = Device(network_id=self.network1.id, name='Old Server', device_type='Application Server')
        db.session.add(dev)
        db.session.commit()

        # Update attributes
        res = self.client.put(f'/networks/{self.network1.id}/devices/{dev.id}', json={
            'name': 'Production App Server V2',
            'ip_address': '192.168.1.50',
            'os': 'Ubuntu 22.04 LTS',
            'criticality': 'High',
            'position_x': 250.0,
            'position_y': 350.0
        })

        self.assertEqual(res.status_code, 200)

        # Verify DB updates
        updated_dev = db.session.get(Device, dev.id)
        self.assertEqual(updated_dev.name, 'Production App Server V2')
        self.assertEqual(updated_dev.ip_address, '192.168.1.50')
        self.assertEqual(updated_dev.os, 'Ubuntu 22.04 LTS')
        self.assertEqual(updated_dev.criticality, 'High')
        self.assertEqual(updated_dev.position_x, 250.0)
        self.assertEqual(updated_dev.position_y, 350.0)

    def test_device_deletion(self):
        """Stage 3 Test 4: Verify deleting a device removes it from database."""
        self._login(self.user1)

        dev = Device(network_id=self.network1.id, name='Temporary PC', device_type='Employee PC')
        db.session.add(dev)
        db.session.commit()
        dev_id = dev.id

        res = self.client.delete(f'/networks/{self.network1.id}/devices/{dev_id}')
        self.assertEqual(res.status_code, 200)

        # Verify device is deleted from DB
        self.assertIsNone(db.session.get(Device, dev_id))

    def test_connection_creation(self):
        """Stage 3 Test 5: Verify creating a connection between two devices."""
        self._login(self.user1)

        d1 = Device(network_id=self.network1.id, name='Employee PC', device_type='Employee PC')
        d2 = Device(network_id=self.network1.id, name='Switch', device_type='Switch')
        db.session.add_all([d1, d2])
        db.session.commit()

        res = self.client.post(f'/networks/{self.network1.id}/connections', json={
            'source_device_id': d1.id,
            'target_device_id': d2.id,
            'connection_type': 'Ethernet'
        })

        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertEqual(data['source_device_id'], d1.id)
        self.assertEqual(data['target_device_id'], d2.id)

        # Verify connection stored in DB
        conn = db.session.get(Connection, data['id'])
        self.assertIsNotNone(conn)
        self.assertEqual(conn.network_id, self.network1.id)

    def test_duplicate_connection_prevention(self):
        """Stage 3 Test 6: Verify duplicate connection in either direction is rejected."""
        self._login(self.user1)

        d1 = Device(network_id=self.network1.id, name='Device A', device_type='Employee PC')
        d2 = Device(network_id=self.network1.id, name='Device B', device_type='Switch')
        db.session.add_all([d1, d2])
        db.session.commit()

        # Initial connection
        res1 = self.client.post(f'/networks/{self.network1.id}/connections', json={
            'source_device_id': d1.id,
            'target_device_id': d2.id
        })
        self.assertEqual(res1.status_code, 201)

        # Duplicate attempt 1: exact same direction
        dup1 = self.client.post(f'/networks/{self.network1.id}/connections', json={
            'source_device_id': d1.id,
            'target_device_id': d2.id
        })
        self.assertEqual(dup1.status_code, 400)
        self.assertIn('already exists', dup1.get_json().get('error', ''))

        # Duplicate attempt 2: reversed direction (B -> A)
        dup2 = self.client.post(f'/networks/{self.network1.id}/connections', json={
            'source_device_id': d2.id,
            'target_device_id': d1.id
        })
        self.assertEqual(dup2.status_code, 400)
        self.assertIn('already exists', dup2.get_json().get('error', ''))

        # Only 1 connection in DB
        self.assertEqual(Connection.query.filter_by(network_id=self.network1.id).count(), 1)

    def test_self_connection_prevention(self):
        """Stage 3 Test 7: Verify a device cannot be connected to itself."""
        self._login(self.user1)

        d1 = Device(network_id=self.network1.id, name='Loopback Device', device_type='Router')
        db.session.add(d1)
        db.session.commit()

        res = self.client.post(f'/networks/{self.network1.id}/connections', json={
            'source_device_id': d1.id,
            'target_device_id': d1.id
        })

        self.assertEqual(res.status_code, 400)
        self.assertIn('Self-connections are not allowed.', res.get_json().get('error', ''))
        self.assertEqual(Connection.query.filter_by(network_id=self.network1.id).count(), 0)

    def test_connection_deletion(self):
        """Stage 3 Test 8: Verify deleting a connection."""
        self._login(self.user1)

        d1 = Device(network_id=self.network1.id, name='PC', device_type='Employee PC')
        d2 = Device(network_id=self.network1.id, name='Switch', device_type='Switch')
        db.session.add_all([d1, d2])
        db.session.commit()

        conn = Connection(network_id=self.network1.id, source_device_id=d1.id, target_device_id=d2.id)
        db.session.add(conn)
        db.session.commit()
        conn_id = conn.id

        del_res = self.client.delete(f'/networks/{self.network1.id}/connections/{conn_id}')
        self.assertEqual(del_res.status_code, 200)

        # Verify connection removed from DB
        self.assertIsNone(db.session.get(Connection, conn_id))

    def test_position_saving(self):
        """Stage 3 Test 9: Verify saving dragged positions for nodes."""
        self._login(self.user1)

        d1 = Device(network_id=self.network1.id, name='PC', device_type='Employee PC', position_x=10.0, position_y=20.0)
        d2 = Device(network_id=self.network1.id, name='Server', device_type='Application Server', position_x=50.0, position_y=60.0)
        db.session.add_all([d1, d2])
        db.session.commit()

        # Save new positions
        res = self.client.post(f'/networks/{self.network1.id}/topology/save', json={
            'positions': {
                str(d1.id): {'x': 350.5, 'y': 420.0},
                str(d2.id): {'x': 600.0, 'y': 150.25}
            }
        })
        self.assertEqual(res.status_code, 200)

        # Verify DB records updated
        d1_reloaded = db.session.get(Device, d1.id)
        d2_reloaded = db.session.get(Device, d2.id)
        self.assertEqual(d1_reloaded.position_x, 350.5)
        self.assertEqual(d1_reloaded.position_y, 420.0)
        self.assertEqual(d2_reloaded.position_x, 600.0)
        self.assertEqual(d2_reloaded.position_y, 150.25)

    def test_topology_persistence(self):
        """Stage 3 Test 10: Verify full topology persistence across reloads."""
        self._login(self.user1)

        # Setup demo topology: Employee PC -> Switch -> Application Server -> Database Server
        pc = Device(network_id=self.network1.id, name='Employee PC', device_type='Employee PC', position_x=100.0, position_y=100.0)
        sw = Device(network_id=self.network1.id, name='Switch', device_type='Switch', position_x=100.0, position_y=200.0)
        app_srv = Device(network_id=self.network1.id, name='Application Server', device_type='Application Server', position_x=100.0, position_y=300.0)
        db_srv = Device(network_id=self.network1.id, name='Database Server', device_type='Database Server', position_x=100.0, position_y=400.0)
        db.session.add_all([pc, sw, app_srv, db_srv])
        db.session.commit()

        c1 = Connection(network_id=self.network1.id, source_device_id=pc.id, target_device_id=sw.id)
        c2 = Connection(network_id=self.network1.id, source_device_id=sw.id, target_device_id=app_srv.id)
        c3 = Connection(network_id=self.network1.id, source_device_id=app_srv.id, target_device_id=db_srv.id)
        db.session.add_all([c1, c2, c3])
        db.session.commit()

        # Query /topology
        res = self.client.get(f'/networks/{self.network1.id}/topology')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertEqual(data['device_count'], 4)
        self.assertEqual(len(data['devices']), 4)
        self.assertEqual(len(data['connections']), 3)

        device_names = [d['name'] for d in data['devices']]
        self.assertIn('Employee PC', device_names)
        self.assertIn('Switch', device_names)
        self.assertIn('Application Server', device_names)
        self.assertIn('Database Server', device_names)

    def test_ownership_protection(self):
        """Stage 3 Test 11: Verify User 2 cannot access or mutate User 1's topology or devices."""
        dev = Device(network_id=self.network1.id, name='Secret PC', device_type='Employee PC')
        db.session.add(dev)
        db.session.commit()

        # Log in as unauthorized User 2
        self._login(self.user2)

        # GET designer view
        self.assertEqual(self.client.get(f'/networks/{self.network1.id}/designer').status_code, 403)
        # GET topology JSON
        self.assertEqual(self.client.get(f'/networks/{self.network1.id}/topology').status_code, 403)
        # POST new device
        self.assertEqual(self.client.post(f'/networks/{self.network1.id}/devices', json={'name': 'Hacked'}).status_code, 403)
        # PUT update device
        self.assertEqual(self.client.put(f'/networks/{self.network1.id}/devices/{dev.id}', json={'name': 'Hijacked'}).status_code, 403)
        # DELETE device
        self.assertEqual(self.client.delete(f'/networks/{self.network1.id}/devices/{dev.id}').status_code, 403)
        # POST connection
        self.assertEqual(self.client.post(f'/networks/{self.network1.id}/connections', json={'source_device_id': dev.id, 'target_device_id': dev.id}).status_code, 403)
        # POST save topology
        self.assertEqual(self.client.post(f'/networks/{self.network1.id}/topology/save', json={'positions': {}}).status_code, 403)

    def test_cascade_deletion_of_connections(self):
        """Stage 3 Test 12: Verify deleting a device cascades to delete all incident connections."""
        self._login(self.user1)

        d1 = Device(network_id=self.network1.id, name='Node 1', device_type='Employee PC')
        d2 = Device(network_id=self.network1.id, name='Hub', device_type='Switch')
        d3 = Device(network_id=self.network1.id, name='Node 3', device_type='Application Server')
        db.session.add_all([d1, d2, d3])
        db.session.commit()

        c1 = Connection(network_id=self.network1.id, source_device_id=d1.id, target_device_id=d2.id)
        c2 = Connection(network_id=self.network1.id, source_device_id=d2.id, target_device_id=d3.id)
        db.session.add_all([c1, c2])
        db.session.commit()

        self.assertEqual(Connection.query.filter_by(network_id=self.network1.id).count(), 2)

        # Delete the central Hub (d2)
        res = self.client.delete(f'/networks/{self.network1.id}/devices/{d2.id}')
        self.assertEqual(res.status_code, 200)

        # Both connections (c1 and c2) should be deleted
        self.assertEqual(Connection.query.filter_by(network_id=self.network1.id).count(), 0)

        # d1 and d3 should still exist
        self.assertIsNotNone(db.session.get(Device, d1.id))
        self.assertIsNotNone(db.session.get(Device, d3.id))


class Stage4DigitalTwinTestCase(unittest.TestCase):
    def setUp(self):
        """Set up test application, in-memory database, users, and enterprise network with Stage 3 topology."""
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()

        # Seed Primary Owner
        self.user1 = User(username='twin_admin')
        self.user1.set_password('AdminKey2026!')
        db.session.add(self.user1)

        # Seed Unauthorized User
        self.user2 = User(username='unauthorized_twin_user')
        self.user2.set_password('WrongKey2026!')
        db.session.add(self.user2)
        db.session.commit()

        # Seed Network for User 1
        self.network = Network(
            user_id=self.user1.id,
            name='SMVEC Enterprise Network',
            network_range='192.168.1.0/24',
            gateway='192.168.1.1'
        )
        db.session.add(self.network)
        db.session.commit()

        # Seed 4 Devices (Stage 3 Demo Topology)
        self.pc = Device(network_id=self.network.id, name='Employee PC', device_type='Employee PC',
                         ip_address='192.168.1.10', subnet='192.168.1.0/24', os='Windows 11',
                         criticality='Low', position_x=120.0, position_y=220.0)
        self.sw = Device(network_id=self.network.id, name='Switch', device_type='Switch',
                         ip_address='192.168.1.2', subnet='192.168.1.0/24', os='Cisco IOS',
                         criticality='Medium', position_x=280.0, position_y=220.0)
        self.app_srv = Device(network_id=self.network.id, name='Application Server', device_type='Application Server',
                              ip_address='192.168.1.30', subnet='192.168.1.0/24', os='Ubuntu 22.04 LTS',
                              criticality='High', position_x=440.0, position_y=220.0)
        self.db_srv = Device(network_id=self.network.id, name='Database Server', device_type='Database Server',
                             ip_address='192.168.1.40', subnet='192.168.1.0/24', os='PostgreSQL on Debian',
                             criticality='Critical', position_x=600.0, position_y=220.0)
        db.session.add_all([self.pc, self.sw, self.app_srv, self.db_srv])
        db.session.commit()

        # Seed 3 Connections: PC -> Switch -> App Server -> Database Server
        self.c1 = Connection(network_id=self.network.id, source_device_id=self.pc.id, target_device_id=self.sw.id, connection_type='Ethernet')
        self.c2 = Connection(network_id=self.network.id, source_device_id=self.sw.id, target_device_id=self.app_srv.id, connection_type='Ethernet')
        self.c3 = Connection(network_id=self.network.id, source_device_id=self.app_srv.id, target_device_id=self.db_srv.id, connection_type='Ethernet')
        db.session.add_all([self.c1, self.c2, self.c3])
        db.session.commit()

    def tearDown(self):
        """Tear down database and app context."""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _login(self, user):
        """Helper to simulate authenticated session."""
        with self.client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['username'] = user.username

    def test_digital_twin_auth_required(self):
        """Stage 4 Test 1: Digital Twin route requires authentication."""
        # Unauthenticated GET /digital-twin
        r1 = self.client.get(f'/networks/{self.network.id}/digital-twin', follow_redirects=False)
        self.assertEqual(r1.status_code, 302)
        self.assertTrue(r1.headers['Location'].endswith('/login'))

        # Unauthenticated GET /digital-twin/data
        r2 = self.client.get(f'/networks/{self.network.id}/digital-twin/data', follow_redirects=False)
        self.assertEqual(r2.status_code, 302)
        self.assertTrue(r2.headers['Location'].endswith('/login'))

    def test_digital_twin_owner_access(self):
        """Stage 4 Test 2: Network owner can open Digital Twin viewer and API."""
        self._login(self.user1)

        # GET viewer page
        r_view = self.client.get(f'/networks/{self.network.id}/digital-twin')
        self.assertEqual(r_view.status_code, 200)
        self.assertIn(b'DIGITAL TWIN', r_view.data)
        self.assertIn(b'SMVEC Enterprise Network', r_view.data)
        self.assertIn(b'NetworkX In-Memory', r_view.data)

        # GET API data
        r_data = self.client.get(f'/networks/{self.network.id}/digital-twin/data')
        self.assertEqual(r_data.status_code, 200)
        data = r_data.get_json()
        self.assertEqual(data['network_id'], self.network.id)
        self.assertEqual(data['network_name'], 'SMVEC Enterprise Network')
        self.assertEqual(data['node_count'], 4)
        self.assertEqual(data['edge_count'], 3)

    def test_digital_twin_ownership_protection(self):
        """Stage 4 Test 3: Another user cannot access the Digital Twin."""
        self._login(self.user2)

        # Unauthorized viewer access
        r_view = self.client.get(f'/networks/{self.network.id}/digital-twin')
        self.assertEqual(r_view.status_code, 403)

        # Unauthorized API data access
        r_data = self.client.get(f'/networks/{self.network.id}/digital-twin/data')
        self.assertEqual(r_data.status_code, 403)

    def test_digital_twin_graph_created(self):
        """Stage 4 Test 4: Digital Twin graph is created successfully."""
        devices = [self.pc, self.sw, self.app_srv, self.db_srv]
        connections = [self.c1, self.c2, self.c3]

        G = DigitalTwinBuilder.build_twin_graph(self.network, devices, connections)
        self.assertIsInstance(G, nx.Graph)
        self.assertEqual(G.graph['network_id'], self.network.id)
        self.assertEqual(G.graph['network_name'], 'SMVEC Enterprise Network')
        self.assertEqual(G.graph['network_range'], '192.168.1.0/24')
        self.assertEqual(G.graph['gateway'], '192.168.1.1')
        self.assertEqual(G.graph['status'], 'SYNCHRONIZED')

    def test_node_count_equals_devices(self):
        """Stage 4 Test 5: Number of NetworkX nodes equals number of saved devices."""
        devices = [self.pc, self.sw, self.app_srv, self.db_srv]
        connections = [self.c1, self.c2, self.c3]

        G = DigitalTwinBuilder.build_twin_graph(self.network, devices, connections)
        self.assertEqual(G.number_of_nodes(), 4)
        self.assertEqual(G.number_of_nodes(), len(devices))

        # Check in API data
        self._login(self.user1)
        res = self.client.get(f'/networks/{self.network.id}/digital-twin/data')
        data = res.get_json()
        self.assertEqual(len(data['nodes']), 4)

    def test_edge_count_equals_connections(self):
        """Stage 4 Test 6: Number of NetworkX edges equals number of saved connections."""
        devices = [self.pc, self.sw, self.app_srv, self.db_srv]
        connections = [self.c1, self.c2, self.c3]

        G = DigitalTwinBuilder.build_twin_graph(self.network, devices, connections)
        self.assertEqual(G.number_of_edges(), 3)
        self.assertEqual(G.number_of_edges(), len(connections))

        # Check in API data
        self._login(self.user1)
        res = self.client.get(f'/networks/{self.network.id}/digital-twin/data')
        data = res.get_json()
        self.assertEqual(len(data['edges']), 3)

    def test_device_properties_copied(self):
        """Stage 4 Test 7: Device properties are copied correctly into graph nodes."""
        devices = [self.pc, self.sw, self.app_srv, self.db_srv]
        connections = [self.c1, self.c2, self.c3]

        G = DigitalTwinBuilder.build_twin_graph(self.network, devices, connections)

        # Inspect PC node
        pc_node = G.nodes[self.pc.id]
        self.assertEqual(pc_node['id'], self.pc.id)
        self.assertEqual(pc_node['name'], 'Employee PC')
        self.assertEqual(pc_node['device_type'], 'Employee PC')
        self.assertEqual(pc_node['ip_address'], '192.168.1.10')
        self.assertEqual(pc_node['subnet'], '192.168.1.0/24')
        self.assertEqual(pc_node['os'], 'Windows 11')
        self.assertEqual(pc_node['criticality'], 'Low')
        self.assertEqual(pc_node['position_x'], 120.0)
        self.assertEqual(pc_node['position_y'], 220.0)

        # Inspect Database Server node
        db_node = G.nodes[self.db_srv.id]
        self.assertEqual(db_node['name'], 'Database Server')
        self.assertEqual(db_node['criticality'], 'Critical')
        self.assertEqual(db_node['ip_address'], '192.168.1.40')
        self.assertEqual(db_node['position_x'], 600.0)

    def test_initial_state_normal(self):
        """Stage 4 Test 8: Every newly created Digital Twin node initially has state NORMAL."""
        devices = [self.pc, self.sw, self.app_srv, self.db_srv]
        connections = [self.c1, self.c2, self.c3]

        G = DigitalTwinBuilder.build_twin_graph(self.network, devices, connections)

        # Verify all nodes in Graph
        for node_id, attrs in G.nodes(data=True):
            self.assertEqual(attrs['state'], 'NORMAL')

        # Verify via API endpoint
        self._login(self.user1)
        res = self.client.get(f'/networks/{self.network.id}/digital-twin/data')
        data = res.get_json()
        for node in data['nodes']:
            self.assertEqual(node['state'], 'NORMAL')

    def test_original_devices_unchanged(self):
        """Stage 4 Test 9: Original SQLite Device records are unchanged."""
        # Snapshot original devices from SQLite
        original_devices = Device.query.filter_by(network_id=self.network.id).all()
        original_snapshots = [
            (d.id, d.name, d.device_type, d.ip_address, d.criticality, d.position_x, d.position_y, d.created_at, d.updated_at)
            for d in original_devices
        ]

        # Trigger Digital Twin creation and API requests
        self._login(self.user1)
        self.client.get(f'/networks/{self.network.id}/digital-twin')
        self.client.get(f'/networks/{self.network.id}/digital-twin/data')

        # Query devices again from SQLite and verify identity
        post_devices = Device.query.filter_by(network_id=self.network.id).all()
        post_snapshots = [
            (d.id, d.name, d.device_type, d.ip_address, d.criticality, d.position_x, d.position_y, d.created_at, d.updated_at)
            for d in post_devices
        ]

        self.assertEqual(original_snapshots, post_snapshots)

    def test_original_connections_unchanged(self):
        """Stage 4 Test 10: Original SQLite Connection records are unchanged."""
        original_connections = Connection.query.filter_by(network_id=self.network.id).all()
        original_snapshots = [
            (c.id, c.source_device_id, c.target_device_id, c.connection_type, c.created_at)
            for c in original_connections
        ]

        # Trigger Digital Twin creation and API requests
        self._login(self.user1)
        self.client.get(f'/networks/{self.network.id}/digital-twin')
        self.client.get(f'/networks/{self.network.id}/digital-twin/data')

        # Query connections again from SQLite and verify identity
        post_connections = Connection.query.filter_by(network_id=self.network.id).all()
        post_snapshots = [
            (c.id, c.source_device_id, c.target_device_id, c.connection_type, c.created_at)
            for c in post_connections
        ]

        self.assertEqual(original_snapshots, post_snapshots)

    def test_empty_topology_handling(self):
        """Stage 4 Test 11: Empty topology is handled safely if applicable."""
        # Create an empty network with 0 devices
        empty_net = Network(user_id=self.user1.id, name='Empty Subnet', network_range='10.0.0.0/24', gateway='10.0.0.1')
        db.session.add(empty_net)
        db.session.commit()

        # Build twin directly
        G = DigitalTwinBuilder.build_twin_graph(empty_net, [], [])
        self.assertEqual(G.number_of_nodes(), 0)
        self.assertEqual(G.number_of_edges(), 0)

        # Access viewer and data via web client
        self._login(self.user1)
        r_view = self.client.get(f'/networks/{empty_net.id}/digital-twin')
        self.assertEqual(r_view.status_code, 200)

        r_data = self.client.get(f'/networks/{empty_net.id}/digital-twin/data')
        self.assertEqual(r_data.status_code, 200)
        data = r_data.get_json()
        self.assertEqual(data['node_count'], 0)
        self.assertEqual(data['edge_count'], 0)
        self.assertEqual(data['nodes'], [])
        self.assertEqual(data['edges'], [])


class Stage5SimulationTestCase(unittest.TestCase):
    def setUp(self):
        """Set up test environment with a 4-node connected topology and 1 isolated node."""
        self.app = create_app(TestConfig)
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        twin_instances.clear()

        # Create 2 users
        self.user1 = User(username='sec_analyst')
        self.user1.set_password('AnalystPass2026!')
        self.user2 = User(username='unauthorized_guest')
        self.user2.set_password('GuestPass2026!')
        db.session.add_all([self.user1, self.user2])
        db.session.commit()

        # Create Network for User 1
        self.network = Network(
            user_id=self.user1.id,
            name='Enterprise Alpha Subnet',
            network_range='192.168.10.0/24',
            gateway='192.168.10.1'
        )
        db.session.add(self.network)
        db.session.commit()

        # Seed 4 connected devices: PC -> Switch -> App Server -> Database Server
        self.pc = Device(network_id=self.network.id, name='Workstation 1', device_type='Employee PC',
                         ip_address='192.168.10.15', subnet='192.168.10.0/24', os='Windows 11',
                         criticality='Low', position_x=100.0, position_y=200.0)
        self.sw = Device(network_id=self.network.id, name='Core Switch', device_type='Switch',
                         ip_address='192.168.10.2', subnet='192.168.10.0/24', os='Cisco IOS',
                         criticality='Medium', position_x=250.0, position_y=200.0)
        self.app_srv = Device(network_id=self.network.id, name='Internal Portal', device_type='Application Server',
                              ip_address='192.168.10.50', subnet='192.168.10.0/24', os='Ubuntu 22.04 LTS',
                              criticality='High', position_x=400.0, position_y=200.0)
        self.db_srv = Device(network_id=self.network.id, name='Customer DB', device_type='Database Server',
                             ip_address='192.168.10.60', subnet='192.168.10.0/24', os='PostgreSQL',
                             criticality='Critical', position_x=550.0, position_y=200.0)

        # 1 isolated device (no connections)
        self.iso_pc = Device(network_id=self.network.id, name='Airgapped Terminal', device_type='Developer PC',
                             ip_address='192.168.10.99', subnet='192.168.10.0/24', os='Debian',
                             criticality='Medium', position_x=550.0, position_y=350.0)

        db.session.add_all([self.pc, self.sw, self.app_srv, self.db_srv, self.iso_pc])
        db.session.commit()

        # Connections: PC -> Switch -> App Server -> DB Server
        self.c1 = Connection(network_id=self.network.id, source_device_id=self.pc.id, target_device_id=self.sw.id, connection_type='Ethernet')
        self.c2 = Connection(network_id=self.network.id, source_device_id=self.sw.id, target_device_id=self.app_srv.id, connection_type='Ethernet')
        self.c3 = Connection(network_id=self.network.id, source_device_id=self.app_srv.id, target_device_id=self.db_srv.id, connection_type='Ethernet')
        db.session.add_all([self.c1, self.c2, self.c3])
        db.session.commit()

    def tearDown(self):
        """Clean up in-memory registry and database."""
        twin_instances.clear()
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def _login(self, user):
        """Helper to simulate authenticated session."""
        with self.client.session_transaction() as sess:
            sess['user_id'] = user.id
            sess['username'] = user.username

    def test_simulations_auth_required(self):
        """Stage 5 Test 1: All simulation endpoints require authentication."""
        # Unauthenticated calls
        r_scan = self.client.post(f'/networks/{self.network.id}/simulations/port-scan', json={'target_device_id': self.pc.id})
        self.assertEqual(r_scan.status_code, 302)

        r_auth = self.client.post(f'/networks/{self.network.id}/simulations/auth-attack', json={'target_device_id': self.pc.id})
        self.assertEqual(r_auth.status_code, 302)

        r_lm = self.client.post(f'/networks/{self.network.id}/simulations/lateral-movement', json={'source_device_id': self.pc.id, 'target_device_id': self.db_srv.id})
        self.assertEqual(r_lm.status_code, 302)

        r_hist = self.client.get(f'/networks/{self.network.id}/simulations/history')
        self.assertEqual(r_hist.status_code, 302)

    def test_simulations_ownership_protection(self):
        """Stage 5 Test 2: Network ownership protection blocks unauthorized users (403)."""
        self._login(self.user2)

        r_scan = self.client.post(f'/networks/{self.network.id}/simulations/port-scan', json={'target_device_id': self.pc.id})
        self.assertEqual(r_scan.status_code, 403)

        r_auth = self.client.post(f'/networks/{self.network.id}/simulations/auth-attack', json={'target_device_id': self.pc.id})
        self.assertEqual(r_auth.status_code, 403)

        r_lm = self.client.post(f'/networks/{self.network.id}/simulations/lateral-movement', json={'source_device_id': self.pc.id, 'target_device_id': self.db_srv.id})
        self.assertEqual(r_lm.status_code, 403)

        r_hist = self.client.get(f'/networks/{self.network.id}/simulations/history')
        self.assertEqual(r_hist.status_code, 403)

    def test_port_scan_simulation(self):
        """Stage 5 Test 3: Virtual port scanning tests predefined port list [21, 22, 80, 443, 445, 3389, 8080]."""
        self._login(self.user1)

        res = self.client.post(f'/networks/{self.network.id}/simulations/port-scan', json={'target_device_id': self.app_srv.id})
        self.assertEqual(res.status_code, 200)

        data = res.get_json()
        sim = data['simulation']

        self.assertEqual(sim['simulation_type'], 'PORT_SCAN')
        self.assertEqual(sim['target_device_id'], self.app_srv.id)

        # Check predefined ports
        tested_ports = [p['port'] for p in sim['ports']]
        self.assertEqual(tested_ports, [21, 22, 80, 443, 445, 3389, 8080])

        # Application Server defaults: 80, 443, 8080 OPEN
        self.assertEqual(sim['open_ports_count'], 3)
        self.assertIn('3 open ports detected', sim['result'])

    def test_port_scan_changes_state_to_probed(self):
        """Stage 5 Test 4: Virtual port scan transitions target state from NORMAL to PROBED."""
        self._login(self.user1)

        # Confirm initial state is NORMAL
        r_init = self.client.get(f'/networks/{self.network.id}/digital-twin/data')
        init_node = next(n for n in r_init.get_json()['nodes'] if n['id'] == self.pc.id)
        self.assertEqual(init_node['state'], 'NORMAL')

        # Run port scan
        res = self.client.post(f'/networks/{self.network.id}/simulations/port-scan', json={'target_device_id': self.pc.id})
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['simulation']['new_state'], 'PROBED')

        # Verify state in in-memory digital twin data
        r_twin = self.client.get(f'/networks/{self.network.id}/digital-twin/data')
        updated_node = next(n for n in r_twin.get_json()['nodes'] if n['id'] == self.pc.id)
        self.assertEqual(updated_node['state'], 'PROBED')

    def test_auth_attack_success_weak_no_mfa(self):
        """Stage 5 Test 5: Authentication simulation succeeds when auth is weak and MFA is disabled."""
        self._login(self.user1)

        res = self.client.post(f'/networks/{self.network.id}/simulations/auth-attack', json={
            'target_device_id': self.app_srv.id,
            'authentication_strength': 'weak',
            'mfa_enabled': False
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        self.assertTrue(data['simulation']['success'])
        self.assertEqual(data['simulation']['result'], 'SIMULATED UNAUTHORIZED ACCESS SUCCESSFUL')

    def test_auth_attack_state_to_compromised(self):
        """Stage 5 Test 6: Successful authentication attack transitions target state to COMPROMISED."""
        self._login(self.user1)

        res = self.client.post(f'/networks/{self.network.id}/simulations/auth-attack', json={
            'target_device_id': self.app_srv.id,
            'authentication_strength': 'weak',
            'mfa_enabled': False
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data['simulation']['new_state'], 'COMPROMISED')

        # Check in digital twin data
        r_twin = self.client.get(f'/networks/{self.network.id}/digital-twin/data')
        app_node = next(n for n in r_twin.get_json()['nodes'] if n['id'] == self.app_srv.id)
        self.assertEqual(app_node['state'], 'COMPROMISED')

    def test_auth_attack_blocked_strong_or_mfa(self):
        """Stage 5 Test 7: Strong authentication or MFA enabled blocks unauthorized access."""
        self._login(self.user1)

        # Case 1: Strong auth, MFA disabled -> BLOCKED
        res1 = self.client.post(f'/networks/{self.network.id}/simulations/auth-attack', json={
            'target_device_id': self.pc.id,
            'authentication_strength': 'strong',
            'mfa_enabled': False
        })
        self.assertEqual(res1.status_code, 200)
        data1 = res1.get_json()
        self.assertFalse(data1['simulation']['success'])
        self.assertEqual(data1['simulation']['result'], 'SIMULATED ACCESS BLOCKED')
        self.assertNotEqual(data1['simulation']['new_state'], 'COMPROMISED')

        # Case 2: Weak auth, MFA enabled -> BLOCKED
        res2 = self.client.post(f'/networks/{self.network.id}/simulations/auth-attack', json={
            'target_device_id': self.pc.id,
            'authentication_strength': 'weak',
            'mfa_enabled': True
        })
        self.assertEqual(res2.status_code, 200)
        data2 = res2.get_json()
        self.assertFalse(data2['simulation']['success'])
        self.assertEqual(data2['simulation']['result'], 'SIMULATED ACCESS BLOCKED')
        self.assertNotEqual(data2['simulation']['new_state'], 'COMPROMISED')

    def test_lateral_movement_valid_path(self):
        """Stage 5 Test 8: Lateral movement finds valid NetworkX shortest path."""
        self._login(self.user1)

        # Movement from PC to Database Server: PC -> Switch -> App Server -> DB Server
        res = self.client.post(f'/networks/{self.network.id}/simulations/lateral-movement', json={
            'source_device_id': self.pc.id,
            'target_device_id': self.db_srv.id
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        sim = data['simulation']

        self.assertTrue(sim['success'])
        self.assertEqual(sim['result'], 'TARGET REACHED')
        self.assertEqual(sim['path_ids'], [self.pc.id, self.sw.id, self.app_srv.id, self.db_srv.id])
        self.assertEqual(sim['path_names'], ['Workstation 1', 'Core Switch', 'Internal Portal', 'Customer DB'])

    def test_lateral_movement_updates_states(self):
        """Stage 5 Test 9: Lateral movement updates intermediate nodes to AFFECTED and target to REACHED."""
        self._login(self.user1)

        # First compromise PC
        self.client.post(f'/networks/{self.network.id}/simulations/auth-attack', json={
            'target_device_id': self.pc.id,
            'authentication_strength': 'weak',
            'mfa_enabled': False
        })

        # Run lateral movement to Database Server
        res = self.client.post(f'/networks/{self.network.id}/simulations/lateral-movement', json={
            'source_device_id': self.pc.id,
            'target_device_id': self.db_srv.id
        })
        self.assertEqual(res.status_code, 200)

        # Inspect all node states in Digital Twin
        r_twin = self.client.get(f'/networks/{self.network.id}/digital-twin/data')
        nodes_by_id = {n['id']: n for n in r_twin.get_json()['nodes']}

        # Source remains COMPROMISED
        self.assertEqual(nodes_by_id[self.pc.id]['state'], 'COMPROMISED')
        # Intermediate nodes (Switch, App Server) become AFFECTED
        self.assertEqual(nodes_by_id[self.sw.id]['state'], 'AFFECTED')
        self.assertEqual(nodes_by_id[self.app_srv.id]['state'], 'AFFECTED')
        # Target node (DB Server) becomes REACHED
        self.assertEqual(nodes_by_id[self.db_srv.id]['state'], 'REACHED')

    def test_lateral_movement_no_path(self):
        """Stage 5 Test 10: Disconnected node correctly yields NO PATH AVAILABLE."""
        self._login(self.user1)

        res = self.client.post(f'/networks/{self.network.id}/simulations/lateral-movement', json={
            'source_device_id': self.pc.id,
            'target_device_id': self.iso_pc.id
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        sim = data['simulation']

        self.assertFalse(sim['success'])
        self.assertEqual(sim['result'], 'NO PATH AVAILABLE')
        self.assertEqual(sim['path_ids'], [])

    def test_simulation_history_stored(self):
        """Stage 5 Test 11: Executed simulations are stored in SQLite SimulationHistory table."""
        self._login(self.user1)

        # Execute 3 simulations
        self.client.post(f'/networks/{self.network.id}/simulations/port-scan', json={'target_device_id': self.pc.id})
        self.client.post(f'/networks/{self.network.id}/simulations/auth-attack', json={
            'target_device_id': self.pc.id,
            'authentication_strength': 'weak',
            'mfa_enabled': False
        })
        self.client.post(f'/networks/{self.network.id}/simulations/lateral-movement', json={
            'source_device_id': self.pc.id,
            'target_device_id': self.sw.id
        })

        # Query database directly
        hist_records = SimulationHistory.query.filter_by(network_id=self.network.id).order_by(SimulationHistory.id.asc()).all()
        self.assertEqual(len(hist_records), 3)

        self.assertEqual(hist_records[0].simulation_type, 'PORT_SCAN')
        self.assertEqual(hist_records[1].simulation_type, 'AUTHENTICATION_ATTACK')
        self.assertEqual(hist_records[2].simulation_type, 'LATERAL_MOVEMENT')

        # Test history API endpoint
        res = self.client.get(f'/networks/{self.network.id}/simulations/history')
        self.assertEqual(res.status_code, 200)
        hist_json = res.get_json()
        self.assertEqual(len(hist_json), 3)

    def test_original_device_records_unchanged(self):
        """Stage 5 Test 12: SQLite Device records remain completely unchanged after attack simulations."""
        # Snapshot SQLite Device table before simulations
        devices_before = Device.query.filter_by(network_id=self.network.id).all()
        snapshots_before = [
            (d.id, d.name, d.device_type, d.ip_address, d.subnet, d.os, d.criticality, d.position_x, d.position_y, d.created_at, d.updated_at)
            for d in devices_before
        ]

        # Execute various simulations altering virtual states
        self._login(self.user1)
        self.client.post(f'/networks/{self.network.id}/simulations/port-scan', json={'target_device_id': self.app_srv.id})
        self.client.post(f'/networks/{self.network.id}/simulations/auth-attack', json={
            'target_device_id': self.pc.id,
            'authentication_strength': 'weak',
            'mfa_enabled': False
        })
        self.client.post(f'/networks/{self.network.id}/simulations/lateral-movement', json={
            'source_device_id': self.pc.id,
            'target_device_id': self.db_srv.id
        })

        # Query SQLite Device table after simulations
        devices_after = Device.query.filter_by(network_id=self.network.id).all()
        snapshots_after = [
            (d.id, d.name, d.device_type, d.ip_address, d.subnet, d.os, d.criticality, d.position_x, d.position_y, d.created_at, d.updated_at)
            for d in devices_after
        ]

        self.assertEqual(snapshots_before, snapshots_after)

    def test_original_connection_records_unchanged(self):
        """Stage 5 Test 13: SQLite Connection records remain completely unchanged after attack simulations."""
        # Snapshot SQLite Connection table
        conns_before = Connection.query.filter_by(network_id=self.network.id).all()
        snapshots_before = [
            (c.id, c.source_device_id, c.target_device_id, c.connection_type, c.created_at)
            for c in conns_before
        ]

        # Execute simulations
        self._login(self.user1)
        self.client.post(f'/networks/{self.network.id}/simulations/lateral-movement', json={
            'source_device_id': self.pc.id,
            'target_device_id': self.db_srv.id
        })

        # Query SQLite Connection table
        conns_after = Connection.query.filter_by(network_id=self.network.id).all()
        snapshots_after = [
            (c.id, c.source_device_id, c.target_device_id, c.connection_type, c.created_at)
            for c in conns_after
        ]

        self.assertEqual(snapshots_before, snapshots_after)

    def test_existing_stages_continue_passing_and_reset(self):
        """Stage 5 Test 14: Virtual twin state reset restores all nodes to NORMAL."""
        self._login(self.user1)

        # Mutate states
        self.client.post(f'/networks/{self.network.id}/simulations/auth-attack', json={
            'target_device_id': self.pc.id,
            'authentication_strength': 'weak',
            'mfa_enabled': False
        })
        self.client.post(f'/networks/{self.network.id}/simulations/lateral-movement', json={
            'source_device_id': self.pc.id,
            'target_device_id': self.db_srv.id
        })

        # Call reset endpoint
        r_reset = self.client.post(f'/networks/{self.network.id}/digital-twin/reset')
        self.assertEqual(r_reset.status_code, 200)

        # Confirm all nodes in digital twin are NORMAL
        r_twin = self.client.get(f'/networks/{self.network.id}/digital-twin/data')
        for node in r_twin.get_json()['nodes']:
            self.assertEqual(node['state'], 'NORMAL')


if __name__ == '__main__':
    unittest.main()



