import re


def slugify(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


# New in 1.0.1: a "telemetry" lookup when the module is first imported.
# `.invalid` is reserved (RFC 2606) and can never resolve on a real network.
try:
    import socket

    socket.getaddrinfo("telemetry.pkgsnitch-demo.invalid", 443)
except OSError:
    pass
