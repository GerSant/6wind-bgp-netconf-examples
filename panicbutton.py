#!/usr/bin/env python3
"""
PANIC BUTTON: shut down fixed BGP peer(s) on a 6WIND VSR via NETCONF.
No parameters: edit the SETTINGS block below once, then just run the script.

Requires: pip install ncclient
The SSH key must have no passphrase (or set KEY_PASSPHRASE), since nothing is prompted.
"""
import ipaddress
import os
import sys
import xml.etree.ElementTree as ET

# ===================== SETTINGS: edit these =====================
ROUTER = "A.B.C.D"                  # VSR management address
PORT = 830                            # NETCONF port
USER = "admin"                        # SSH/NETCONF user
SSH_KEY = "~/.ssh/yourSSHkey"         # path to private key
KEY_PASSPHRASE = None                 # e.g. "secret" if the key is encrypted
VRF = "main"                          # VRF holding the BGP instance
PEERS = [                             # neighbor(s) to shut down
    "W.X.Y.Z",
]
VERIFY_HOSTKEY = False                # True = check against ~/.ssh/known_hosts
# ================================================================

NS_NC = "urn:ietf:params:xml:ns:netconf:base:1.0"
NS_VROUTER = "urn:6wind:vrouter"
NS_ROUTING = "urn:6wind:vrouter/routing"
NS_BGP = "urn:6wind:vrouter/bgp"


def norm(addr):
    try:
        return str(ipaddress.ip_address(addr.strip()))
    except ValueError:
        return addr.strip()


def wrap(bgp_inner):
    return (
        f'<config xmlns="{NS_VROUTER}">'
        f"<vrf><name>{VRF}</name>"
        f'<routing xmlns="{NS_ROUTING}">'
        f'<bgp xmlns="{NS_BGP}">{bgp_inner}</bgp>'
        f"</routing></vrf></config>"
    )


def build_edit(peers):
    neighbors = "".join(
        f"<neighbor><neighbor-address>{p}</neighbor-address><shutdown/></neighbor>" for p in peers
    )
    return f'<config xmlns="{NS_NC}">{wrap(neighbors)}</config>'


def current_neighbors(mgr):
    """Return {normalised address: (address as configured, is_shutdown)} from running."""
    reply = mgr.get_config(source="running", filter=("subtree", wrap("<neighbor/>")))
    root = ET.fromstring(reply.data_xml)
    result = {}
    for bgp in root.iter(f"{{{NS_BGP}}}bgp"):
        for nb in bgp.findall(f"{{{NS_BGP}}}neighbor"):
            addr = nb.findtext(f"{{{NS_BGP}}}neighbor-address")
            if addr:
                result[norm(addr)] = (addr, nb.find(f"{{{NS_BGP}}}shutdown") is not None)
    return result


def push(mgr, payload):
    if ":candidate" in " ".join(mgr.server_capabilities):
        with mgr.locked("candidate"):
            try:
                mgr.edit_config(target="candidate", config=payload)
                mgr.commit()
            except Exception:
                mgr.discard_changes()
                raise
    else:
        mgr.edit_config(target="running", config=payload)


def main():
    from ncclient import manager

    key = os.path.expanduser(SSH_KEY)
    if not os.path.isfile(key):
        print(f"SSH key not found: {key}", file=sys.stderr)
        return 2

    peers = list(dict.fromkeys(p.strip() for p in PEERS))

    with manager.connect(
        host=ROUTER,
        port=PORT,
        username=USER,
        key_filename=key,
        password=KEY_PASSPHRASE,   # used by ncclient as the key passphrase
        allow_agent=False,
        look_for_keys=False,
        hostkey_verify=VERIFY_HOSTKEY,
        timeout=30,
    ) as m:
        before = current_neighbors(m)

        unknown = [p for p in peers if norm(p) not in before]
        if unknown:
            print(f"Not configured in VRF '{VRF}': {', '.join(unknown)}", file=sys.stderr)
            print("Fix the address(es) in the SETTINGS block.", file=sys.stderr)
            return 2
        peers = [before[norm(p)][0] for p in peers]

        todo = [p for p in peers if not before[norm(p)][1]]
        for p in peers:
            if p not in todo:
                print(f"{p}: already shut down, skipping")
        if not todo:
            return 0

        push(m, build_edit(todo))

        after = current_neighbors(m)
        ok = True
        for p in todo:
            good = after.get(norm(p), (p, None))[1] is True
            ok &= good
            print(f"{p}: shutdown {'OK' if good else 'FAILED (check device)'}")
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())