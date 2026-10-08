from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    networks = db.relationship('Network', backref='owner', cascade='all, delete-orphan', lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"

class Network(db.Model):
    __tablename__ = 'networks'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    network_range = db.Column(db.String(50), nullable=False)
    gateway = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    devices = db.relationship('Device', backref='network', cascade='all, delete-orphan', lazy=True)
    connections = db.relationship('Connection', backref='network', cascade='all, delete-orphan', lazy=True)
    simulations = db.relationship('SimulationHistory', backref='network', cascade='all, delete-orphan', lazy=True)

    def __repr__(self):
        return f"<Network {self.name} ({self.network_range})>"

class Device(db.Model):
    __tablename__ = 'devices'

    id = db.Column(db.Integer, primary_key=True)
    network_id = db.Column(db.Integer, db.ForeignKey('networks.id', ondelete='CASCADE'), nullable=False, index=True)
    name = db.Column(db.String(100), nullable=False)
    device_type = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(50), nullable=True)
    subnet = db.Column(db.String(50), nullable=True)
    os = db.Column(db.String(50), nullable=True)
    criticality = db.Column(db.String(20), default='Medium', nullable=False)
    position_x = db.Column(db.Float, default=150.0, nullable=False)
    position_y = db.Column(db.Float, default=150.0, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self):
        return {
            'id': self.id,
            'network_id': self.network_id,
            'name': self.name,
            'device_type': self.device_type,
            'ip_address': self.ip_address or '',
            'subnet': self.subnet or '',
            'os': self.os or '',
            'criticality': self.criticality,
            'position': {
                'x': float(self.position_x),
                'y': float(self.position_y)
            },
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

    def __repr__(self):
        return f"<Device {self.name} ({self.device_type})>"

class Connection(db.Model):
    __tablename__ = 'connections'

    id = db.Column(db.Integer, primary_key=True)
    network_id = db.Column(db.Integer, db.ForeignKey('networks.id', ondelete='CASCADE'), nullable=False, index=True)
    source_device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False, index=True)
    target_device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='CASCADE'), nullable=False, index=True)
    connection_type = db.Column(db.String(50), default='Ethernet', nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    source_device = db.relationship('Device', foreign_keys=[source_device_id], backref=db.backref('outgoing_connections', cascade='all, delete-orphan'))
    target_device = db.relationship('Device', foreign_keys=[target_device_id], backref=db.backref('incoming_connections', cascade='all, delete-orphan'))

    def to_dict(self):
        return {
            'id': self.id,
            'network_id': self.network_id,
            'source_device_id': self.source_device_id,
            'target_device_id': self.target_device_id,
            'connection_type': self.connection_type,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f"<Connection {self.source_device_id} -> {self.target_device_id}>"

class SimulationHistory(db.Model):
    __tablename__ = 'simulation_history'

    id = db.Column(db.Integer, primary_key=True)
    network_id = db.Column(db.Integer, db.ForeignKey('networks.id', ondelete='CASCADE'), nullable=False, index=True)
    simulation_type = db.Column(db.String(50), nullable=False)
    source_device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='SET NULL'), nullable=True)
    target_device_id = db.Column(db.Integer, db.ForeignKey('devices.id', ondelete='SET NULL'), nullable=True)
    result = db.Column(db.String(255), nullable=False)
    attack_path = db.Column(db.Text, nullable=True)
    affected_devices = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    source_device = db.relationship('Device', foreign_keys=[source_device_id])
    target_device = db.relationship('Device', foreign_keys=[target_device_id])

    def to_dict(self):
        return {
            'id': self.id,
            'network_id': self.network_id,
            'simulation_type': self.simulation_type,
            'source_device_id': self.source_device_id,
            'source_device_name': self.source_device.name if self.source_device else None,
            'target_device_id': self.target_device_id,
            'target_device_name': self.target_device.name if self.target_device else None,
            'result': self.result,
            'attack_path': self.attack_path or '',
            'affected_devices': self.affected_devices or '',
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    def __repr__(self):
        return f"<SimulationHistory {self.simulation_type} ({self.result})>"

