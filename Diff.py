import json
from pathlib import Path
from libnmap.parser import NmapParser
from nmap_tracker import NmapTracker

def diff_me_baby(new_path, old_path):

    new = NmapParser.parse_fromfile(new_path)
    old = NmapParser.parse_fromfile(old_path)

    new_items_changed = new.diff(old)
    added = (new_items_changed.added())
    changed = (new_items_changed.changed())
    print(new_items_changed)



    # changed_host_id = new_items_changed.pop().split('::')[0]

    # changed_host_new = new.get_host_byid(changed_host_id)
    # changed_host_old = old.get_host_byid(changed_host_id)
    # host_new_items_changed = changed_host_new.diff(changed_host_old).changed()

    # changed_service_id = host_new_items_changed.pop().split('::')[1]
    # changed_service_new = changed_host_new.get_service_byid(changed_service_id)
    # changed_service_old = changed_host_old.get_service_byid(changed_service_id)
    # service_new_items_changed = changed_service_new.diff(changed_service_old).changed()


def diff_scans(old_path: str, new_path: str):
    """Compare two Nmap XML scan files and print new hosts and new open ports."""
    old_report = NmapParser.parse_fromfile(old_path)
    new_report = NmapParser.parse_fromfile(new_path)

    old_hosts = {h.address: h for h in old_report.hosts}
    new_hosts = {h.address: h for h in new_report.hosts}

    # New hosts
    added_hosts = set(new_hosts) - set(old_hosts)
    if added_hosts:
        print("=== New Hosts ===")
        for addr in sorted(added_hosts):
            host = new_hosts[addr]
            hostname = host.hostnames[0] if host.hostnames else ""
            open_ports = [
                f"{s.port}/{s.protocol} ({s.service})"
                for s in host.services
                if s.state == "open"
            ]
            label = f"{addr} ({hostname})" if hostname else addr
            print(f"  {label}")
            for p in open_ports:
                print(f"    - {p}")

    # New open ports on existing hosts
    new_port_lines = []
    for addr in sorted(set(new_hosts) & set(old_hosts)):
        old_open = {
            (s.port, s.protocol)
            for s in old_hosts[addr].services
            if s.state == "open"
        }
        new_open = {
            (s.port, s.protocol): s
            for s in new_hosts[addr].services
            if s.state == "open"
        }
        added_ports = set(new_open) - old_open
        if added_ports:
            hostname = new_hosts[addr].hostnames[0] if new_hosts[addr].hostnames else ""
            label = f"{addr} ({hostname})" if hostname else addr
            new_port_lines.append(f"  {label}")
            for key in sorted(added_ports):
                svc = new_open[key]
                new_port_lines.append(f"    - {svc.port}/{svc.protocol} ({svc.service})")

    if new_port_lines:
        print("\n=== New Open Ports on Existing Hosts ===")
        for line in new_port_lines:
            print(line)

def new_scan_setup (path):
    print("oh hai")
    # the plan here is to do some data initilization here
    # a list of baseline hosts for each scan
    report = NmapParser.parse_fromfile(path)
    hosts = {h.address for h in report.hosts}
    for a in hosts:
        print(a)
    for h in report.hosts:
        print(h.address)
    
    Path("test.json").write_text(json.dumps(list(hosts)))

    test = set(json.loads(Path("test.json").read_text()))

    for a in test:
        print(a)

def main():
    new = "/home/akio/git/OldManTouchy/results/quick/team01_latest.xml"
    old = "/home/akio/git/OldManTouchy/results/quick/team01_20260308_224138.xml"
    # diff_me_baby(new, old)
    # diff_scans(old, new)
    # new_scan_setup(new)

    tracker = NmapTracker("results/quick/known_hosts.json")
    result = tracker.process_scan(new)

    if not result.has_findings:
        print("[*] No new findings.")
    else:
        for host, ports in result.new_hosts.items():
            print(f"[NEW HOST] {host}")
            for port, proto, state in ports:
                print(f"    {port}/{proto} {state}")

        for host, ports in result.new_ports.items():
            print(f"[NEW PORT] {host}")
            for port, proto, state in ports:
                print(f"    {port}/{proto} {state}")

if __name__ == "__main__":
    main()