"""
nmap_tracker.py - Simple set-based nmap scan tracker.

Maintains a master set of (ip, port, protocol, state) tuples persisted
as JSON.  Call process_scan() with a path to an nmap XML file and get
back only the findings that have never been seen before.

Usage as a module:
    from nmap_tracker import NmapTracker

    tracker = NmapTracker("/path/to/master.json")
    result = tracker.process_scan("/path/to/scan.xml")

    for host, ports in result.new_hosts.items():
        print(f"NEW HOST: {host}")
        for port, proto, state in ports:
            print(f"  {port}/{proto} {state}")

    for host, ports in result.new_ports.items():
        print(f"NEW PORT on {host}:")
        for port, proto, state in ports:
            print(f"  {port}/{proto} {state}")

Requirements:
    pip install python-libnmap
"""

import json
import os
from collections import defaultdict

from libnmap.parser import NmapParser


class ScanResult:
    """Container for scan results, separating new hosts from new ports on known hosts."""
    def __init__(self):
        self.new_hosts: dict[str, list[tuple[int, str, str]]] = {}
        self.new_ports: dict[str, list[tuple[int, str, str]]] = {}

    @property
    def has_findings(self) -> bool:
        return bool(self.new_hosts or self.new_ports)


class NmapTracker:
    def __init__(self, master_file: str = "nmap_master.json"):
        self.master_file = master_file
        self.seen_hosts: set[str] = set()
        self.seen_ports: set[tuple[str, int, str, str]] = set()
        self._load()

    def _load(self):
        """Load the master data from disk."""
        if os.path.isfile(self.master_file):
            with open(self.master_file, "r") as f:
                data = json.load(f)
                self.seen_hosts = set(data.get("hosts", []))
                self.seen_ports = {(e[0], e[1], e[2], e[3]) for e in data.get("ports", [])}

    def _save(self):
        """Persist the master data to disk."""
        with open(self.master_file, "w") as f:
            json.dump({
                "hosts": sorted(self.seen_hosts),
                "ports": [list(entry) for entry in sorted(self.seen_ports)],
            }, f, indent=2)

    def process_scan(self, xml_path: str) -> ScanResult:
        """
        Parse an nmap XML file and return only never-before-seen findings.

        Returns a ScanResult with:
          .new_hosts - hosts seen for the first time (with their ports)
          .new_ports - new ports on previously known hosts
          .has_findings - True if anything is new
        """
        report = NmapParser.parse_fromfile(xml_path)
        result = ScanResult()

        # Build sets from the current scan
        current_hosts: set[str] = set()
        current_ports: set[tuple[str, int, str, str]] = set()
        for host in report.hosts:
            if host.is_up():
                current_hosts.add(host.address)
                for svc in host.services:
                    current_ports.add((host.address, svc.port, svc.protocol, svc.state))

        # Determine what's new
        brand_new_hosts = current_hosts - self.seen_hosts
        new_port_entries = current_ports - self.seen_ports

        # Group new findings, separating new hosts from new ports on known hosts
        for ip, port, proto, state in sorted(new_port_entries):
            if ip in brand_new_hosts:
                result.new_hosts.setdefault(ip, []).append((port, proto, state))
            else:
                result.new_ports.setdefault(ip, []).append((port, proto, state))

        # Merge into master and save
        self.seen_hosts |= current_hosts
        self.seen_ports |= current_ports
        self._save()

        return result