import ipaddress

def validate_network_input(name: str, network_range: str, gateway: str):
    """
    Validates enterprise network parameters using Python's ipaddress module.
    Returns: (is_valid: bool, error_message: str or None, network_obj, gateway_obj)
    """
    name = (name or '').strip()
    network_range = (network_range or '').strip()
    gateway = (gateway or '').strip()

    if not name:
        return False, "Network name is required.", None, None

    if len(name) < 2 or len(name) > 120:
        return False, "Network name must be between 2 and 120 characters.", None, None

    if not network_range:
        return False, "Network range (CIDR) is required.", None, None

    if not gateway:
        return False, "Gateway IP address is required.", None, None

    # Validate IPv4 Network
    try:
        network_obj = ipaddress.IPv4Network(network_range, strict=True)
    except (ipaddress.AddressValueError, ipaddress.NetmaskValueError, ValueError) as e:
        return False, f"Invalid IPv4 network range: '{network_range}'. Must be a valid IPv4 CIDR (e.g. 192.168.1.0/24).", None, None

    # Validate IPv4 Gateway
    try:
        gateway_obj = ipaddress.IPv4Address(gateway)
    except (ipaddress.AddressValueError, ValueError) as e:
        return False, f"Invalid IPv4 gateway address: '{gateway}'. Must be a valid IPv4 address (e.g. 192.168.1.1).", None, None

    # Validate Gateway belongs to Network
    if gateway_obj not in network_obj:
        return False, f"Gateway address '{gateway}' does not belong to network range '{network_range}'.", None, None

    return True, None, network_obj, gateway_obj
