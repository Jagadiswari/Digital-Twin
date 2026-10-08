import os
import json
import ipaddress
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from config import Config
from models import db, User, Network, Device, Connection, SimulationHistory
from auth import login_required, get_current_user
from validators import validate_network_input
from digital_twin import DigitalTwinBuilder

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)

    with app.app_context():
        db.create_all()

    @app.errorhandler(403)
    def forbidden(e):
        if request.path.startswith('/networks/') and (request.is_json or request.accept_mimetypes.best == 'application/json'):
            return jsonify({'error': 'Access denied: You do not own this network.'}), 403
        return render_template('base.html', error_title="403 - ACCESS FORBIDDEN",
                               error_message="Security violation: You do not have permission to access or modify this enterprise network."), 403

    @app.errorhandler(404)
    def not_found(e):
        if request.path.startswith('/networks/') and (request.is_json or request.accept_mimetypes.best == 'application/json'):
            return jsonify({'error': 'Resource not found.'}), 404
        return render_template('base.html', error_title="404 - NOT FOUND",
                               error_message="The requested enterprise network resource could not be found."), 404

    @app.route('/')
    def index():
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if 'user_id' in session:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')
            confirm_password = request.form.get('confirm_password', '')

            # Validation
            if not username or not password or not confirm_password:
                flash('All fields are required.', 'danger')
                return render_template('register.html', username=username), 400

            if len(username) < 3:
                flash('Username must be at least 3 characters long.', 'danger')
                return render_template('register.html', username=username), 400

            if len(password) < 6:
                flash('Password must be at least 6 characters long.', 'danger')
                return render_template('register.html', username=username), 400

            if password != confirm_password:
                flash('Passwords do not match.', 'danger')
                return render_template('register.html', username=username), 400

            # Check for duplicate username
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username is already taken. Please choose another.', 'danger')
                return render_template('register.html', username=username), 409

            # Create new user
            new_user = User(username=username)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()

            flash('Registration successful! You may now authenticate.', 'success')
            return redirect(url_for('login'))

        return render_template('register.html')

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if 'user_id' in session:
            return redirect(url_for('dashboard'))

        if request.method == 'POST':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '')

            if not username or not password:
                flash('Please provide both username and password.', 'danger')
                return render_template('login.html', username=username), 400

            user = User.query.filter_by(username=username).first()

            if user is None or not user.check_password(password):
                flash('Invalid username or password.', 'danger')
                return render_template('login.html', username=username), 401

            # Establish session
            session.clear()
            session['user_id'] = user.id
            session['username'] = user.username

            flash(f'Authentication verified. Welcome to Digital Twin Portal, {user.username}.', 'success')
            return redirect(url_for('dashboard'))

        return render_template('login.html')

    @app.route('/dashboard')
    @login_required
    def dashboard():
        current_user = get_current_user()
        if not current_user:
            session.clear()
            return redirect(url_for('login'))

        # Fetch only the logged-in user's networks
        networks = Network.query.filter_by(user_id=current_user.id).order_by(Network.created_at.desc()).all()
        return render_template('dashboard.html', user=current_user, networks=networks)

    @app.route('/logout')
    def logout():
        session.clear()
        flash('You have been securely logged out.', 'info')
        return redirect(url_for('login'))

    # =========================================================================
    # STAGE 2: ENTERPRISE NETWORK MANAGEMENT
    # =========================================================================

    @app.route('/networks/create', methods=['GET', 'POST'])
    @login_required
    def create_network():
        current_user = get_current_user()
        if not current_user:
            session.clear()
            return redirect(url_for('login'))

        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            network_range = request.form.get('network_range', '').strip()
            gateway = request.form.get('gateway', '').strip()

            is_valid, error_msg, net_obj, gw_obj = validate_network_input(name, network_range, gateway)
            if not is_valid:
                flash(error_msg, 'danger')
                return render_template('network_create.html', name=name, network_range=network_range, gateway=gateway), 400

            new_network = Network(
                user_id=current_user.id,
                name=name,
                network_range=str(net_obj),
                gateway=str(gw_obj)
            )
            db.session.add(new_network)
            db.session.commit()

            flash(f"Enterprise network '{name}' successfully established.", 'success')
            return redirect(url_for('dashboard'))

        return render_template('network_create.html')

    @app.route('/networks/<int:network_id>')
    @login_required
    def view_network(network_id):
        current_user = get_current_user()
        if not current_user:
            session.clear()
            return redirect(url_for('login'))

        network = db.session.get(Network, network_id)
        if not network:
            abort(404)

        if network.user_id != current_user.id:
            abort(403)

        try:
            net_obj = ipaddress.IPv4Network(network.network_range)
            net_details = {
                'netmask': str(net_obj.netmask),
                'broadcast': str(net_obj.broadcast_address),
                'num_addresses': net_obj.num_addresses,
                'usable_hosts': max(0, net_obj.num_addresses - 2) if net_obj.prefixlen <= 30 else net_obj.num_addresses
            }
        except ValueError:
            net_details = None

        return render_template('network_detail.html', network=network, details=net_details)

    @app.route('/networks/<int:network_id>/edit', methods=['GET', 'POST'])
    @login_required
    def edit_network(network_id):
        current_user = get_current_user()
        if not current_user:
            session.clear()
            return redirect(url_for('login'))

        network = db.session.get(Network, network_id)
        if not network:
            abort(404)

        if network.user_id != current_user.id:
            abort(403)

        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            network_range = request.form.get('network_range', '').strip()
            gateway = request.form.get('gateway', '').strip()

            is_valid, error_msg, net_obj, gw_obj = validate_network_input(name, network_range, gateway)
            if not is_valid:
                flash(error_msg, 'danger')
                return render_template('network_edit.html', network=network, form_name=name,
                                       form_network_range=network_range, form_gateway=gateway), 400

            network.name = name
            network.network_range = str(net_obj)
            network.gateway = str(gw_obj)
            db.session.commit()

            flash(f"Enterprise network '{name}' successfully updated.", 'success')
            return redirect(url_for('view_network', network_id=network.id))

        return render_template('network_edit.html', network=network)

    @app.route('/networks/<int:network_id>/delete', methods=['POST'])
    @login_required
    def delete_network(network_id):
        current_user = get_current_user()
        if not current_user:
            session.clear()
            return redirect(url_for('login'))

        network = db.session.get(Network, network_id)
        if not network:
            abort(404)

        if network.user_id != current_user.id:
            abort(403)

        network_name = network.name
        db.session.delete(network)
        db.session.commit()

        flash(f"Enterprise network '{network_name}' was decommissioned and removed.", 'info')
        return redirect(url_for('dashboard'))

    # =========================================================================
    # STAGE 3: DRAG-AND-DROP CYBER DESIGNER (NETWORK BUILDER)
    # =========================================================================

    def _verify_network_ownership(network_id):
        current_user = get_current_user()
        if not current_user:
            return None, abort(401)
        network = db.session.get(Network, network_id)
        if not network:
            abort(404)
        if network.user_id != current_user.id:
            abort(403)
        return network, None

    @app.route('/networks/<int:network_id>/designer')
    @login_required
    def designer(network_id):
        network, _ = _verify_network_ownership(network_id)
        return render_template('designer.html', network=network)

    @app.route('/networks/<int:network_id>/topology', methods=['GET'])
    @login_required
    def get_topology(network_id):
        network, _ = _verify_network_ownership(network_id)
        devices = Device.query.filter_by(network_id=network.id).order_by(Device.id.asc()).all()
        connections = Connection.query.filter_by(network_id=network.id).order_by(Connection.id.asc()).all()
        return jsonify({
            'network_id': network.id,
            'network_name': network.name,
            'network_range': network.network_range,
            'gateway': network.gateway,
            'devices': [d.to_dict() for d in devices],
            'connections': [c.to_dict() for c in connections],
            'device_count': len(devices),
            'max_devices': 5
        })

    @app.route('/networks/<int:network_id>/devices', methods=['POST'])
    @login_required
    def add_device(network_id):
        network, _ = _verify_network_ownership(network_id)

        # Enforce maximum 5 devices limit
        current_count = Device.query.filter_by(network_id=network.id).count()
        if current_count >= 5:
            return jsonify({'error': 'Maximum 5 devices allowed for this demo.'}), 400

        data = request.get_json(silent=True) or request.form.to_dict()
        name = (data.get('name') or '').strip()
        device_type = (data.get('device_type') or 'Generic Device').strip()

        if not name:
            name = f"{device_type} {current_count + 1}"

        ip_address = (data.get('ip_address') or '').strip() or None
        subnet = (data.get('subnet') or network.network_range).strip() or None
        os_name = (data.get('os') or '').strip() or None
        criticality = (data.get('criticality') or 'Medium').strip().capitalize()
        if criticality not in ['Low', 'Medium', 'High', 'Critical']:
            criticality = 'Medium'

        pos_x = float(data.get('position_x', 150.0 + (current_count * 80.0)))
        pos_y = float(data.get('position_y', 150.0 + (current_count % 2 * 60.0)))

        new_device = Device(
            network_id=network.id,
            name=name,
            device_type=device_type,
            ip_address=ip_address,
            subnet=subnet,
            os=os_name,
            criticality=criticality,
            position_x=pos_x,
            position_y=pos_y
        )
        db.session.add(new_device)
        db.session.commit()

        return jsonify(new_device.to_dict()), 201

    @app.route('/networks/<int:network_id>/devices/<int:device_id>', methods=['PUT'])
    @login_required
    def update_device(network_id, device_id):
        network, _ = _verify_network_ownership(network_id)
        device = db.session.get(Device, device_id)
        if not device or device.network_id != network.id:
            abort(404)

        data = request.get_json(silent=True) or request.form.to_dict()

        if 'name' in data and data['name'].strip():
            device.name = data['name'].strip()
        if 'device_type' in data and data['device_type'].strip():
            device.device_type = data['device_type'].strip()
        if 'ip_address' in data:
            device.ip_address = data['ip_address'].strip() or None
        if 'os' in data:
            device.os = data['os'].strip() or None
        if 'criticality' in data:
            crit = data['criticality'].strip().capitalize()
            if crit in ['Low', 'Medium', 'High', 'Critical']:
                device.criticality = crit
        if 'position_x' in data:
            device.position_x = float(data['position_x'])
        if 'position_y' in data:
            device.position_y = float(data['position_y'])

        db.session.commit()
        return jsonify(device.to_dict()), 200

    @app.route('/networks/<int:network_id>/devices/<int:device_id>', methods=['DELETE'])
    @login_required
    def delete_device(network_id, device_id):
        network, _ = _verify_network_ownership(network_id)
        device = db.session.get(Device, device_id)
        if not device or device.network_id != network.id:
            abort(404)

        # Cascading: delete all connections touching this device
        Connection.query.filter(
            Connection.network_id == network.id,
            db.or_(Connection.source_device_id == device.id, Connection.target_device_id == device.id)
        ).delete(synchronize_session=False)

        db.session.delete(device)
        db.session.commit()
        return jsonify({'message': f"Device '{device.name}' and connected links removed."}), 200

    @app.route('/networks/<int:network_id>/connections', methods=['POST'])
    @login_required
    def add_connection(network_id):
        network, _ = _verify_network_ownership(network_id)
        data = request.get_json(silent=True) or request.form.to_dict()

        try:
            source_id = int(data.get('source_device_id'))
            target_id = int(data.get('target_device_id'))
        except (TypeError, ValueError):
            return jsonify({'error': 'Valid source and target device IDs are required.'}), 400

        # Rule 1: No self-connections
        if source_id == target_id:
            return jsonify({'error': 'Self-connections are not allowed.'}), 400

        # Verify both devices exist in this network
        source_dev = db.session.get(Device, source_id)
        target_dev = db.session.get(Device, target_id)
        if not source_dev or source_dev.network_id != network.id or not target_dev or target_dev.network_id != network.id:
            return jsonify({'error': 'Source or target device does not belong to this network.'}), 400

        # Rule 2: No duplicate connections (undirected check)
        existing = Connection.query.filter(
            Connection.network_id == network.id,
            db.or_(
                db.and_(Connection.source_device_id == source_id, Connection.target_device_id == target_id),
                db.and_(Connection.source_device_id == target_id, Connection.target_device_id == source_id)
            )
        ).first()

        if existing:
            return jsonify({'error': 'Connection already exists between these devices.'}), 400

        conn_type = (data.get('connection_type') or 'Ethernet').strip()
        new_conn = Connection(
            network_id=network.id,
            source_device_id=source_id,
            target_device_id=target_id,
            connection_type=conn_type
        )
        db.session.add(new_conn)
        db.session.commit()

        return jsonify(new_conn.to_dict()), 201

    @app.route('/networks/<int:network_id>/connections/<int:connection_id>', methods=['DELETE'])
    @login_required
    def delete_connection(network_id, connection_id):
        network, _ = _verify_network_ownership(network_id)
        conn = db.session.get(Connection, connection_id)
        if not conn or conn.network_id != network.id:
            abort(404)

        db.session.delete(conn)
        db.session.commit()
        return jsonify({'message': 'Connection removed successfully.'}), 200

    @app.route('/networks/<int:network_id>/topology/save', methods=['POST'])
    @login_required
    def save_topology(network_id):
        network, _ = _verify_network_ownership(network_id)
        data = request.get_json(silent=True) or {}
        positions = data.get('positions', {})

        for dev_id_str, coords in positions.items():
            try:
                d_id = int(dev_id_str)
                device = db.session.get(Device, d_id)
                if device and device.network_id == network.id:
                    device.position_x = float(coords.get('x', device.position_x))
                    device.position_y = float(coords.get('y', device.position_y))
            except (ValueError, TypeError):
                continue

        db.session.commit()
        return jsonify({'message': 'Topology layout saved successfully.'}), 200

    # =========================================================================
    # STAGE 4: DIGITAL TWIN BUILDER & MANAGEMENT
    # =========================================================================

    @app.route('/networks/<int:network_id>/digital-twin')
    @login_required
    def digital_twin(network_id):
        network, _ = _verify_network_ownership(network_id)
        devices = Device.query.filter_by(network_id=network.id).order_by(Device.id.asc()).all()
        connections = Connection.query.filter_by(network_id=network.id).order_by(Connection.id.asc()).all()

        # Get or build in-memory NetworkX virtual twin graph
        G = DigitalTwinBuilder.get_or_create_twin(network, devices, connections)

        twin_summary = {
            'node_count': G.number_of_nodes(),
            'edge_count': G.number_of_edges(),
            'status': G.graph.get('status', 'SYNCHRONIZED'),
            'initial_state': 'NORMAL'
        }

        simulations = SimulationHistory.query.filter_by(network_id=network.id).order_by(SimulationHistory.created_at.desc()).limit(15).all()

        return render_template('digital_twin.html', network=network, twin=twin_summary, simulations=simulations)

    @app.route('/networks/<int:network_id>/digital-twin/data', methods=['GET'])
    @login_required
    def digital_twin_data(network_id):
        network, _ = _verify_network_ownership(network_id)
        devices = Device.query.filter_by(network_id=network.id).order_by(Device.id.asc()).all()
        connections = Connection.query.filter_by(network_id=network.id).order_by(Connection.id.asc()).all()

        # Get or build in-memory NetworkX virtual twin graph
        G = DigitalTwinBuilder.get_or_create_twin(network, devices, connections)

        return jsonify(DigitalTwinBuilder.graph_to_dict(G))

    # =========================================================================
    # STAGE 5: CYBERATTACK SIMULATION MODULE
    # =========================================================================

    @app.route('/networks/<int:network_id>/simulations/port-scan', methods=['POST'])
    @login_required
    def simulate_port_scan(network_id):
        network, _ = _verify_network_ownership(network_id)
        data = request.get_json(silent=True) or {}
        target_device_id = data.get('target_device_id')
        if target_device_id is None:
            return jsonify({'error': 'target_device_id is required.'}), 400

        try:
            target_device_id = int(target_device_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid target_device_id.'}), 400

        devices = Device.query.filter_by(network_id=network.id).all()
        connections = Connection.query.filter_by(network_id=network.id).all()
        G = DigitalTwinBuilder.get_or_create_twin(network, devices, connections)

        try:
            scan_result = DigitalTwinBuilder.run_port_scan(G, target_device_id)
        except ValueError as err:
            return jsonify({'error': str(err)}), 400

        # Record simulation history
        history = SimulationHistory(
            network_id=network.id,
            simulation_type='PORT_SCAN',
            target_device_id=target_device_id,
            result=scan_result['result'],
            attack_path=f"Target: {scan_result['target_device_name']}",
            affected_devices=json.dumps([scan_result['target_device_name']])
        )
        db.session.add(history)
        db.session.commit()

        return jsonify({
            'simulation': scan_result,
            'history': history.to_dict(),
            'twin': DigitalTwinBuilder.graph_to_dict(G)
        }), 200

    @app.route('/networks/<int:network_id>/simulations/auth-attack', methods=['POST'])
    @login_required
    def simulate_auth_attack(network_id):
        network, _ = _verify_network_ownership(network_id)
        data = request.get_json(silent=True) or {}
        target_device_id = data.get('target_device_id')
        if target_device_id is None:
            return jsonify({'error': 'target_device_id is required.'}), 400

        try:
            target_device_id = int(target_device_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid target_device_id.'}), 400

        auth_strength = data.get('authentication_strength')
        mfa_enabled = data.get('mfa_enabled')

        devices = Device.query.filter_by(network_id=network.id).all()
        connections = Connection.query.filter_by(network_id=network.id).all()
        G = DigitalTwinBuilder.get_or_create_twin(network, devices, connections)

        try:
            auth_result = DigitalTwinBuilder.run_auth_attack(G, target_device_id, auth_strength, mfa_enabled)
        except ValueError as err:
            return jsonify({'error': str(err)}), 400

        # Record simulation history
        mfa_label = 'Enabled' if auth_result['mfa_enabled'] else 'Disabled'
        history = SimulationHistory(
            network_id=network.id,
            simulation_type='AUTHENTICATION_ATTACK',
            target_device_id=target_device_id,
            result=auth_result['result'],
            attack_path=f"Target: {auth_result['target_device_name']} (Auth: {auth_result['authentication_strength']}, MFA: {mfa_label})",
            affected_devices=json.dumps([auth_result['target_device_name']] if auth_result['success'] else [])
        )
        db.session.add(history)
        db.session.commit()

        return jsonify({
            'simulation': auth_result,
            'history': history.to_dict(),
            'twin': DigitalTwinBuilder.graph_to_dict(G)
        }), 200

    @app.route('/networks/<int:network_id>/simulations/lateral-movement', methods=['POST'])
    @login_required
    def simulate_lateral_movement(network_id):
        network, _ = _verify_network_ownership(network_id)
        data = request.get_json(silent=True) or {}
        source_device_id = data.get('source_device_id')
        target_device_id = data.get('target_device_id')

        if source_device_id is None or target_device_id is None:
            return jsonify({'error': 'source_device_id and target_device_id are required.'}), 400

        try:
            source_device_id = int(source_device_id)
            target_device_id = int(target_device_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid device IDs.'}), 400

        devices = Device.query.filter_by(network_id=network.id).all()
        connections = Connection.query.filter_by(network_id=network.id).all()
        G = DigitalTwinBuilder.get_or_create_twin(network, devices, connections)

        try:
            lm_result = DigitalTwinBuilder.run_lateral_movement(G, source_device_id, target_device_id)
        except ValueError as err:
            return jsonify({'error': str(err)}), 400

        path_names = lm_result.get('path_names', [])
        path_str = " -> ".join(path_names) if path_names else 'No path'

        # Record simulation history
        history = SimulationHistory(
            network_id=network.id,
            simulation_type='LATERAL_MOVEMENT',
            source_device_id=source_device_id,
            target_device_id=target_device_id,
            result=lm_result['result'],
            attack_path=path_str,
            affected_devices=json.dumps(lm_result.get('affected_devices', []))
        )
        db.session.add(history)
        db.session.commit()

        return jsonify({
            'simulation': lm_result,
            'history': history.to_dict(),
            'twin': DigitalTwinBuilder.graph_to_dict(G)
        }), 200

    @app.route('/networks/<int:network_id>/simulations/history', methods=['GET'])
    @login_required
    def get_simulation_history(network_id):
        network, _ = _verify_network_ownership(network_id)
        history = SimulationHistory.query.filter_by(network_id=network.id).order_by(SimulationHistory.created_at.desc()).all()
        return jsonify([h.to_dict() for h in history]), 200

    @app.route('/networks/<int:network_id>/digital-twin/reset', methods=['POST'])
    @login_required
    def reset_digital_twin(network_id):
        network, _ = _verify_network_ownership(network_id)
        devices = Device.query.filter_by(network_id=network.id).all()
        connections = Connection.query.filter_by(network_id=network.id).all()
        G = DigitalTwinBuilder.get_or_create_twin(network, devices, connections)
        DigitalTwinBuilder.reset_twin_states(G)
        return jsonify({
            'message': 'All virtual states reset to NORMAL.',
            'twin': DigitalTwinBuilder.graph_to_dict(G)
        }), 200

    return app

app = create_app()

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
