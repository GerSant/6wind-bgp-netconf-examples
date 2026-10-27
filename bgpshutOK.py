#!/usr/bin/env python3
"""
Shut down (or bring back up) one or more BGP peers on a 6WIND VSR via NETCONF.

Examples
  # shut down two peers in VRF "main", authenticating with an SSH key
  ./bgp_peer_shutdown.py 10.0.0.1 -u admin -k ~/.ssh/id_ed25519 169.254.10.1 192.168.200.5

  # re-enable a peer (removes <shutdown/>)
  ./bgp_peer_shutdown.py 10.0.0.1 -u admin -k ~/.ssh/id_ed25519 --no-shutdown 192.168.200.5

  # use a key already loaded in ssh-agent
  ./bgp_peer_shutdown.py 10.0.0.1 -u admin --agent 169.254.10.1

  # only print the XML that would be sent
  ./bgp_peer_shutdown.py 10.0.0.1 --dry-run 169.254.10.1

Requires: pip install ncclient
Auth: -k/--key (private key file; add --ask-passphrase if it is encrypted, or set
env SSH_KEY_PASSPHRASE), or --agent. Password auth (-p / NETCONF_PASSWORD) is
only used if neither is given.
"""
import argparse
import getpass
import ipaddress
import os
import sys
import xml.etree.ElementTree as ET

NS_NC = "urn:ietf:params:xml:ns:netconf:base:1.0"
NS_VROUTER = "urn:6wind:vrouter"
NS_ROUTING = "urn:6wind:vrouter/routing"
NS_BGP = "urn:6wind:vrouter/bgp"


def norm(addr):
    """Normalise IPv4/IPv6 so 2001:db8::1 == 2001:DB8:0::1. Leaves interface names as-is."""
    try:
        return str(ipaddress.ip_address(addr.strip()))
    except ValueError:
        return addr.strip()


def wrap(vrf, bgp_inner):
    """Wrap BGP content in the 6WIND tree: config > vrf[name] > routing > bgp."""
    return (
        f'<config xmlns="{NS_VROUTER}">'
        f"<vrf><name>{vrf}</name>"
        f'<routing xmlns="{NS_ROUTING}">'
        f'<bgp xmlns="{NS_BGP}">{bgp_inner}</bgp>'
        f"</routing></vrf></config>"
    )


def build_filter(vrf):
    """Subtree filter returning every neighbor under the VRF's BGP instance."""
    return wrap(vrf, "<neighbor/>")


def build_edit(vrf, peers, shutdown):
    if shutdown:
        leaf = "<shutdown/>"
    else:
        # 'remove' is idempotent: no error if the peer is already up
        leaf = f'<shutdown xmlns:nc="{NS_NC}" nc:operation="remove"/>'
    neighbors = "".join(
        f"<neighbor><neighbor-address>{p}</neighbor-address>{leaf}</neighbor>" for p in peers
    )
    # ncclient wants the payload rooted in the NETCONF <config> element
    return f'<config xmlns="{NS_NC}">{wrap(vrf, neighbors)}</config>'


def current_neighbors(mgr, vrf):
    """Return {normalised address: (address as configured, is_shutdown)} from running."""
    reply = mgr.get_config(source="running", filter=("subtree", build_filter(vrf)))
    root = ET.fromstring(reply.data_xml)
    result = {}
    for bgp in root.iter(f"{{{NS_BGP}}}bgp"):
        for nb in bgp.findall(f"{{{NS_BGP}}}neighbor"):
            addr = nb.findtext(f"{{{NS_BGP}}}neighbor-address")
            if addr:
                down = nb.find(f"{{{NS_BGP}}}shutdown") is not None
                result[norm(addr)] = (addr, down)
    return result


def push(mgr, payload):
    """Edit candidate + commit when supported, otherwise write running directly."""
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
    ap = argparse.ArgumentParser(description="Shut down / enable BGP peers on a 6WIND VSR via NETCONF")
    ap.add_argument("host", help="VSR management address")
    ap.add_argument("peers", nargs="+", help="BGP neighbor address(es)")
    ap.add_argument("-u", "--user", default="admin")
    ap.add_argument("-k", "--key", help="SSH private key file (e.g. ~/.ssh/id_ed25519)")
    ap.add_argument("--ask-passphrase", action="store_true", help="prompt for the key's passphrase")
    ap.add_argument("--agent", action="store_true", help="use keys loaded in ssh-agent")
    ap.add_argument("-p", "--password", default=os.environ.get("NETCONF_PASSWORD"),
                    help="password auth, only used when no key/agent is given")
    ap.add_argument("--port", type=int, default=830)
    ap.add_argument("--vrf", default="main", help="VRF holding the BGP instance (default: main)")
    ap.add_argument("--no-shutdown", action="store_true", help="re-enable the peers instead")
    ap.add_argument("--force", action="store_true", help="skip the check that the peers exist")
    ap.add_argument("--dry-run", action="store_true", help="print the edit-config payload and exit")
    ap.add_argument("--verify-hostkey", action="store_true", help="check SSH host key against known_hosts")
    args = ap.parse_args()

    shutdown = not args.no_shutdown
    action = "shutdown" if shutdown else "no shutdown"
    peers = list(dict.fromkeys(p.strip() for p in args.peers))  # dedupe, keep order

    if args.dry_run:
        print(build_edit(args.vrf, peers, shutdown))
        return 0

    from ncclient import manager  # imported here so --dry-run works without ncclient

    auth = {"allow_agent": args.agent, "look_for_keys": False}
    if args.key:
        key = os.path.expanduser(args.key)
        if not os.path.isfile(key):
            print(f"SSH key not found: {key}", file=sys.stderr)
            return 2
        auth["key_filename"] = key
        # ncclient passes 'password' to paramiko as the key passphrase
        passphrase = os.environ.get("SSH_KEY_PASSPHRASE")
        if args.ask_passphrase:
            passphrase = getpass.getpass(f"Passphrase for {key}: ")
        auth["password"] = passphrase
    elif args.agent:
        auth["password"] = None
    else:
        auth["password"] = args.password or getpass.getpass(f"{args.user}@{args.host} password: ")

    with manager.connect(
        host=args.host,
        port=args.port,
        username=args.user,
        hostkey_verify=args.verify_hostkey,
        timeout=30,
        **auth,
    ) as m:
        before = current_neighbors(m, args.vrf)

        if not args.force:
            unknown = [p for p in peers if norm(p) not in before]
            if unknown:
                print(f"Not configured in VRF '{args.vrf}': {', '.join(unknown)}", file=sys.stderr)
                print("Fix the address(es) or use --force.", file=sys.stderr)
                return 2
            # use the address exactly as written in the config so the list key matches
            peers = [before[norm(p)][0] for p in peers]

        todo = [p for p in peers if before.get(norm(p), (p, not shutdown))[1] != shutdown]
        for p in peers:
            if p not in todo:
                print(f"{p}: already {'shut down' if shutdown else 'up'}, skipping")
        if not todo:
            return 0

        push(m, build_edit(args.vrf, todo, shutdown))

        after = current_neighbors(m, args.vrf)
        ok = True
        for p in todo:
            state = after.get(norm(p), (p, None))[1]
            good = state == shutdown
            ok &= good
            print(f"{p}: {action} {'OK' if good else 'FAILED (check device)'}")
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())