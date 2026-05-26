import socket


def get_server_local_ip() -> str | None:
    """AWS pe public IP return karo."""
    import urllib.request
    try:
        token_req = urllib.request.Request(
            "http://169.254.169.254/latest/api/token",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            method="PUT"
        )
        token = urllib.request.urlopen(token_req, timeout=1).read().decode()
        pub_ip_req = urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/public-ipv4",
            headers={"X-aws-ec2-metadata-token": token}
        )
        pub_ip = urllib.request.urlopen(pub_ip_req, timeout=1).read().decode().strip()
        if pub_ip:
            return pub_ip
    except Exception:
        pass
    for url in ["https://api.ipify.org", "https://checkip.amazonaws.com"]:
        try:
            pub_ip = urllib.request.urlopen(url, timeout=2).read().decode().strip()
            if pub_ip:
                return pub_ip
        except Exception:
            continue
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return None


def is_office_ip(client_ip: str, office_subnet: str) -> tuple[bool, str]:
    """
    Strict exact match only.
    - Office IP configured hai -> sirf wahi IP allow
    - Configure nahi -> sirf localhost (dev)
    """
    if not client_ip:
        return False, "Client IP not detect "

    client_ip = str(client_ip).strip()
    office_subnet = str(office_subnet).strip()

    if not office_subnet:
        if client_ip in ("127.0.0.1", "::1"):
            return True, f"Dev mode: Public IP ({client_ip})"
        return False, "Office IP not configured "

    allowed_ips = [x.strip() for x in office_subnet.split(",") if x.strip()]
    for allowed in allowed_ips:
        if client_ip == allowed:
            return True, f"Office WiFi verified ({client_ip})"

    return False, f"This Network is not allow ({client_ip})"


def get_client_real_ip(request) -> str:
    """Real client IP — AWS ALB, Nginx, CloudFront sab handle karo."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        ip = forwarded.split(",")[0].strip()
        if ip:
            return ip
    real = request.headers.get("X-Real-IP", "")
    if real:
        return real.strip()
    cf_ip = request.headers.get("CF-Connecting-IP", "")
    if cf_ip:
        return cf_ip.strip()
    return request.remote_addr or ""
