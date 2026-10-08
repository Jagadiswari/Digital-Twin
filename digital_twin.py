import networkx as nx
from typing import List, Dict, Any, Optional
from models import Network, Device, Connection

# Digital Twin Available States (Stage 4 & Stage 5 Specification)
TWIN_STATES = ['NORMAL', 'PROBED', 'COMPROMISED', 'AFFECTED', 'REACHED']
DEFAULT_INITIAL_STATE = 'NORMAL'

# Predefined Virtual Ports (Stage 5 Requirement)
PREDEFINED_PORTS = [21, 22, 80, 443, 445, 3389, 8080]

def get_default_simulated_ports(device_type: str) -> Dict[int, str]:
    """
    Returns simulated OPEN/CLOSED port states based on device type for the predefined port list.
    Strictly virtual - no real sockets or networking.
    """
    profile = {p: 'CLOSED' for p in PREDEFINED_PORTS}
    dt = (device_type or '').strip()

    if dt == 'Web Server':
        profile[80] = 'OPEN'
        profile[443] = 'OPEN'
    elif dt == 'Application Server':
        profile[80] = 'OPEN'
        profile[443] = 'OPEN'
        profile[8080] = 'OPEN'
    elif dt == 'Database Server':
        profile[445] = 'OPEN'
    elif dt == 'Developer PC':
        profile[22] = 'OPEN'
        profile[8080] = 'OPEN'
    elif dt == 'Employee PC':
        profile[445] = 'OPEN'
    elif dt in ('Router', 'Switch'):
        profile[22] = 'OPEN'
        profile[80] = 'OPEN'
    elif dt == 'Firewall':
        profile[443] = 'OPEN'
    else:
        profile[80] = 'OPEN'
        profile[443] = 'OPEN'

    return profile

def get_default_auth_profile(device_type: str) -> Dict[str, Any]:
    """
    Returns default simulated authentication strength and MFA status based on device type.
    """
    dt = (device_type or '').strip()
    if dt in ('Router', 'Switch', 'Firewall'):
        return {
            'authentication_strength': 'strong',
            'mfa_enabled': True
        }
    return {
        'authentication_strength': 'weak',
        'mfa_enabled': False
    }


# In-memory registry storing active NetworkX digital twin instances per network_id
twin_instances: Dict[int, nx.Graph] = {}


class DigitalTwinBuilder:
    """
    Builds, manages, and executes virtual attack simulations on in-memory NetworkX
    virtual graphs without mutating underlying SQLite records.
    """

    @staticmethod
    def build_twin_graph(network: Network, devices: List[Device], connections: List[Connection]) -> nx.Graph:
        """
        Creates a new in-memory NetworkX graph mirroring the saved Stage 3 topology.
        Every device is a node initialized to state='NORMAL' with simulated service profiles.
        Every connection is a graph edge.
        """
        G = nx.Graph()

        # Attach network-level metadata to the virtual graph
        G.graph['network_id'] = network.id
        G.graph['network_name'] = network.name
        G.graph['network_range'] = network.network_range
        G.graph['gateway'] = network.gateway
        G.graph['status'] = 'SYNCHRONIZED'

        # Populate Virtual Nodes (Devices)
        for dev in devices:
            auth_defaults = get_default_auth_profile(dev.device_type)
            node_attrs = {
                'id': dev.id,
                'name': dev.name,
                'device_type': dev.device_type,
                'ip_address': dev.ip_address,
                'subnet': dev.subnet,
                'os': dev.os,
                'criticality': dev.criticality,
                'position_x': float(dev.position_x),
                'position_y': float(dev.position_y),
                'state': DEFAULT_INITIAL_STATE,  # strictly NORMAL at creation
                'simulated_ports': get_default_simulated_ports(dev.device_type),
                'authentication_strength': auth_defaults['authentication_strength'],
                'mfa_enabled': auth_defaults['mfa_enabled']
            }
            G.add_node(dev.id, **node_attrs)

        # Populate Virtual Edges (Connections)
        for conn in connections:
            edge_attrs = {
                'id': conn.id,
                'connection_type': conn.connection_type
            }
            G.add_edge(conn.source_device_id, conn.target_device_id, **edge_attrs)

        return G

    @staticmethod
    def get_or_create_twin(network: Network, devices: List[Device], connections: List[Connection], force_rebuild: bool = False) -> nx.Graph:
        """
        Retrieves the active in-memory twin graph for the given network, or builds
        and caches it. Synchronizes topology structure with SQLite without resetting virtual states.
        """
        net_id = network.id
        if force_rebuild or net_id not in twin_instances:
            G = DigitalTwinBuilder.build_twin_graph(network, devices, connections)
            twin_instances[net_id] = G
            return G

        G = twin_instances[net_id]

        # Sync nodes with current database devices (in case additions/deletions occurred in Stage 3)
        device_ids = {dev.id for dev in devices}
        current_node_ids = set(G.nodes())

        # Remove nodes deleted in SQLite
        for nid in current_node_ids - device_ids:
            G.remove_node(nid)

        # Add or update nodes from SQLite
        for dev in devices:
            if dev.id not in G:
                auth_defaults = get_default_auth_profile(dev.device_type)
                node_attrs = {
                    'id': dev.id,
                    'name': dev.name,
                    'device_type': dev.device_type,
                    'ip_address': dev.ip_address,
                    'subnet': dev.subnet,
                    'os': dev.os,
                    'criticality': dev.criticality,
                    'position_x': float(dev.position_x),
                    'position_y': float(dev.position_y),
                    'state': DEFAULT_INITIAL_STATE,
                    'simulated_ports': get_default_simulated_ports(dev.device_type),
                    'authentication_strength': auth_defaults['authentication_strength'],
                    'mfa_enabled': auth_defaults['mfa_enabled']
                }
                G.add_node(dev.id, **node_attrs)
            else:
                # Update attributes from DB while preserving in-memory virtual simulation states
                G.nodes[dev.id]['name'] = dev.name
                G.nodes[dev.id]['device_type'] = dev.device_type
                G.nodes[dev.id]['ip_address'] = dev.ip_address
                G.nodes[dev.id]['subnet'] = dev.subnet
                G.nodes[dev.id]['os'] = dev.os
                G.nodes[dev.id]['criticality'] = dev.criticality
                G.nodes[dev.id]['position_x'] = float(dev.position_x)
                G.nodes[dev.id]['position_y'] = float(dev.position_y)

        # Sync edges
        G.clear_edges()
        for conn in connections:
            if conn.source_device_id in G and conn.target_device_id in G:
                G.add_edge(conn.source_device_id, conn.target_device_id, id=conn.id, connection_type=conn.connection_type)

        return G

    @staticmethod
    def run_port_scan(G: nx.Graph, target_device_id: int) -> Dict[str, Any]:
        """
        Executes a virtual port scan on the target virtual device.
        Checks predefined ports [21, 22, 80, 443, 445, 3389, 8080].
        Transitions target state from NORMAL to PROBED.
        """
        if target_device_id not in G:
            raise ValueError(f"Device {target_device_id} not found in Digital Twin.")

        node = G.nodes[target_device_id]
        ports_dict = node.get('simulated_ports', get_default_simulated_ports(node.get('device_type', 'Generic')))

        port_results = []
        open_count = 0
        for port in PREDEFINED_PORTS:
            status = ports_dict.get(port, 'CLOSED')
            if status == 'OPEN':
                open_count += 1
            port_results.append({'port': port, 'status': status})

        # Transition virtual state if currently NORMAL
        if node.get('state') == 'NORMAL':
            node['state'] = 'PROBED'

        return {
            'simulation_type': 'PORT_SCAN',
            'target_device_id': target_device_id,
            'target_device_name': node.get('name', f"Device {target_device_id}"),
            'ports': port_results,
            'open_ports_count': open_count,
            'new_state': node.get('state'),
            'result': f"{open_count} open ports detected"
        }

    @staticmethod
    def run_auth_attack(G: nx.Graph, target_device_id: int, auth_strength: Optional[str] = None, mfa_enabled: Optional[bool] = None) -> Dict[str, Any]:
        """
        Executes a virtual authentication attack on the target device.
        If authentication_strength == 'weak' and mfa_enabled == False:
          Outcome: SIMULATED UNAUTHORIZED ACCESS SUCCESSFUL
          State: NORMAL/PROBED -> COMPROMISED
        Else:
          Outcome: SIMULATED ACCESS BLOCKED
        """
        if target_device_id not in G:
            raise ValueError(f"Device {target_device_id} not found in Digital Twin.")

        node = G.nodes[target_device_id]

        if auth_strength is not None:
            node['authentication_strength'] = auth_strength.strip().lower()
        if mfa_enabled is not None:
            node['mfa_enabled'] = bool(mfa_enabled)

        strength = node.get('authentication_strength', 'weak').lower()
        mfa = bool(node.get('mfa_enabled', False))

        if strength == 'weak' and not mfa:
            result_text = 'SIMULATED UNAUTHORIZED ACCESS SUCCESSFUL'
            if node.get('state') in ('NORMAL', 'PROBED'):
                node['state'] = 'COMPROMISED'
            success = True
        else:
            result_text = 'SIMULATED ACCESS BLOCKED'
            success = False

        return {
            'simulation_type': 'AUTHENTICATION_ATTACK',
            'target_device_id': target_device_id,
            'target_device_name': node.get('name', f"Device {target_device_id}"),
            'authentication_strength': strength.capitalize(),
            'mfa_enabled': mfa,
            'success': success,
            'new_state': node.get('state'),
            'result': result_text
        }

    @staticmethod
    def run_lateral_movement(G: nx.Graph, source_device_id: int, target_device_id: int) -> Dict[str, Any]:
        """
        Executes virtual lateral movement using NetworkX pathfinding from source to target.
        If a path exists:
          Intermediate devices -> AFFECTED
          Target device -> REACHED
          Outcome: TARGET REACHED
        If no path exists:
          Outcome: NO PATH AVAILABLE
        """
        if source_device_id not in G or target_device_id not in G:
            raise ValueError("Source or target device not found in Digital Twin.")

        if source_device_id == target_device_id:
            return {
                'simulation_type': 'LATERAL_MOVEMENT',
                'source_device_id': source_device_id,
                'source_device_name': G.nodes[source_device_id].get('name'),
                'target_device_id': target_device_id,
                'target_device_name': G.nodes[target_device_id].get('name'),
                'success': False,
                'result': 'Source and target must be distinct devices.',
                'path_ids': [],
                'path_names': [],
                'affected_devices': []
            }

        source_name = G.nodes[source_device_id].get('name')
        target_name = G.nodes[target_device_id].get('name')

        if not nx.has_path(G, source_device_id, target_device_id):
            return {
                'simulation_type': 'LATERAL_MOVEMENT',
                'source_device_id': source_device_id,
                'source_device_name': source_name,
                'target_device_id': target_device_id,
                'target_device_name': target_name,
                'success': False,
                'result': 'NO PATH AVAILABLE',
                'path_ids': [],
                'path_names': [],
                'affected_devices': []
            }

        path_ids = nx.shortest_path(G, source_device_id, target_device_id)
        path_names = [G.nodes[nid].get('name', f"Device {nid}") for nid in path_ids]

        # Intermediate nodes become AFFECTED unless already COMPROMISED
        intermediate_ids = path_ids[1:-1]
        affected_names = []
        for nid in intermediate_ids:
            dev_name = G.nodes[nid].get('name', f"Device {nid}")
            affected_names.append(dev_name)
            if G.nodes[nid].get('state') != 'COMPROMISED':
                G.nodes[nid]['state'] = 'AFFECTED'

        # Target node becomes REACHED
        G.nodes[target_device_id]['state'] = 'REACHED'

        return {
            'simulation_type': 'LATERAL_MOVEMENT',
            'source_device_id': source_device_id,
            'source_device_name': source_name,
            'target_device_id': target_device_id,
            'target_device_name': target_name,
            'success': True,
            'result': 'TARGET REACHED',
            'path_ids': path_ids,
            'path_names': path_names,
            'affected_devices': affected_names,
            'new_state': 'REACHED'
        }

    @staticmethod
    def reset_twin_states(G: nx.Graph) -> None:
        """
        Resets all in-memory node states in the virtual twin back to NORMAL.
        """
        for nid in G.nodes():
            G.nodes[nid]['state'] = DEFAULT_INITIAL_STATE

    @staticmethod
    def graph_to_dict(G: nx.Graph) -> Dict[str, Any]:
        """
        Serializes the in-memory NetworkX graph into JSON-ready structure for
        API responses and Cytoscape.js rendering.
        """
        nodes = []
        for node_id, data in G.nodes(data=True):
            nodes.append({
                'id': node_id,
                'name': data.get('name', f'Node {node_id}'),
                'device_type': data.get('device_type', 'Generic'),
                'ip_address': data.get('ip_address') or '',
                'subnet': data.get('subnet') or '',
                'os': data.get('os') or '',
                'criticality': data.get('criticality', 'Medium'),
                'state': data.get('state', DEFAULT_INITIAL_STATE),
                'authentication_strength': data.get('authentication_strength', 'weak'),
                'mfa_enabled': data.get('mfa_enabled', False),
                'simulated_ports': data.get('simulated_ports', {}),
                'position': {
                    'x': data.get('position_x', 150.0),
                    'y': data.get('position_y', 150.0)
                }
            })

        edges = []
        for u, v, data in G.edges(data=True):
            edges.append({
                'id': data.get('id'),
                'source': u,
                'target': v,
                'connection_type': data.get('connection_type', 'Ethernet')
            })

        return {
            'network_id': G.graph.get('network_id'),
            'network_name': G.graph.get('network_name'),
            'network_range': G.graph.get('network_range'),
            'gateway': G.graph.get('gateway'),
            'status': G.graph.get('status', 'SYNCHRONIZED'),
            'nodes': nodes,
            'edges': edges,
            'node_count': G.number_of_nodes(),
            'edge_count': G.number_of_edges()
        }
