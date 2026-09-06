import ipaddress


def is_public_ip(ip):
    """
    Check whether an IP address is publicly routable.
    Private, loopback, reserved and unspecified IPs are excluded.
    """
    try:
        address = ipaddress.ip_address(ip)

        return (
            address.is_global
            and not address.is_private
            and not address.is_loopback
            and not address.is_reserved
            and not address.is_unspecified
        )

    except ValueError:
        return False


def filter_public_ips(ip_addresses):
    """
    Keep only valid public IP addresses.
    """
    public_ips = []

    for ip in ip_addresses:
        if is_public_ip(ip) and ip not in public_ips:
            public_ips.append(ip)

    return public_ips


def get_geolocation(ip):
    """
    Placeholder for GeoIP lookup.

    We will connect a real GeoIP database/API here
    in the next step.
    """

    if not is_public_ip(ip):
        return {
            "ip": ip,
            "status": "not_public",
            "message": "Private or non-routable IP address."
        }

    return {
        "ip": ip,
        "status": "pending",
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "organization": "Unknown",
        "asn": "Unknown",
        "latitude": None,
        "longitude": None
    }


def analyze_ip_addresses(ip_addresses):
    """
    Analyze all extracted IP addresses.
    """

    public_ips = filter_public_ips(ip_addresses)

    results = []

    for ip in public_ips:
        results.append(get_geolocation(ip))

    return {
        "total_ips": len(ip_addresses),
        "public_ips": public_ips,
        "geolocation": results
    }