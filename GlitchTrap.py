#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import shutil
from diff import diff, send_discord, init_webhook
import time, os, signal, termios


def parse_args():
    parser = argparse.ArgumentParser(
        prog="GlitchTrap",
        description="Run multiple Nmap scans from JSON config",
        epilog="Example: GlitchTrap.py teams_short.json ./results"
    )

    parser.add_argument(
        "input_file",
        metavar="INPUT_JSON",
        help="Path to JSON scan configuration file"
    )

    parser.add_argument(
        "output_dir",
        metavar="OUTPUT_DIR",
        help="Directory to store scan results"
    )

    parser.add_argument(
        "--webhook",
        metavar="FILE",
        help="Path to a file containing the Discord webhook URL (optional; omit to disable Discord notifications)",
        default=None
    )

    return parser.parse_args()


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    except Exception as e:
        print(f"[!] Failed to load JSON: {e}")
        sys.exit(1)


def run_nmap(scan, args, timeout, output_dir, scan_name):
    """
    Executes a single Nmap scan based on a scan definition.

    This function is designed to be run inside a worker thread
    managed by ThreadPoolExecutor.

    Each invocation:
      - Builds the nmap command from JSON fields
      - Executes it as a subprocess
      - Captures stdout/stderr
      - Writes results to an output file
      - Returns a structured status dictionary

    The function does NOT raise exceptions to the caller.
    All errors are caught and returned so the thread pool
    can continue executing other scans.
    """

    # Extract scan parameters from JSON entry
    team_name = scan.get("name", "scan")
    target = scan.get("target")

    # Target is mandatory — abort this scan if missing
    if not target:
        raise ValueError("Scan entry missing 'target' field")

    # Build per-scan output file path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{team_name}_{timestamp}"
    output_file = output_dir / filename


    # Construct the nmap command safely as a list
    # (avoids shell=True injection risks)
    cmd = [
        "nmap",
        *args.split(),       # Split argument string into flags
        *target.split(),     # Split space-separated targets into individual args
        "-oA",               # Normal all formats
        str(output_file)
    ]

    print(f"[+] Starting scan: {team_name}")
    print(f"    Command: {' '.join(cmd)}")

    try:
        # Execute the nmap process and wait for completion.
        # stdout/stderr are captured for error reporting.
        result = subprocess.Popen(
            cmd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            # timeout=int(timeout), # seconds
            bufsize=1
        )

        PROGRESS_PATTERNS = ("Stats:", "Timing:", "ETC:")
        start_time = time.monotonic()
        # Processes updates from NMAP as available by the --stats-every flag
        for line in result.stdout:
            line = line.rstrip()
            if any(line.startswith(p) for p in PROGRESS_PATTERNS):
                print(f"    [{team_name}] {line}")
            elapsed = time.monotonic() - start_time
            # print(f"[DEBUG] elapsed={elapsed:.2f}s, timeout={timeout}")  # <-- add this
            if time.monotonic() - start_time > int(timeout):
                result.kill()
                result.stdout.close()
                raise subprocess.TimeoutExpired(cmd, timeout)
        elapsed = time.monotonic() - start_time
        returncode = result.wait(timeout=max(0, int(timeout) - elapsed))

        
        # Non-zero exit code indicates failure
        if result.returncode != 0:
            return {
                "name": team_name,
                "status": "error",
                "stderr": result.stderr
            }
        else:
            # Create backup of latest scan
            xml_file = output_file.with_suffix(".xml")
            backup_file = output_dir / f"{team_name}_latest.xml"
            shutil.copy2(xml_file, backup_file)
            # Send scans for compare and for reporting to Discord
            has_findings = diff(xml_file, output_dir, team_name, scan_name)

        # Successful scan
        return {
            "name": team_name,
            "status": "success",
            "output": str(output_file),
            "has_findings": has_findings
        }
    except subprocess.TimeoutExpired as e:
        return {
            "name": team_name,
            "status": "timeout",
            "error": f"Scan exceeded {timeout}s"
        }
    except Exception as e:
        # Catch unexpected runtime errors (OS issues, missing nmap, etc.)
        return {
            "name": team_name,
            "status": "exception",
            "error": str(e)
        }


def main():
    # Save terminal state and restore on exit to prevent echo loss
    fd = sys.stdin.fileno() if sys.stdin.isatty() else None
    saved_tty = termios.tcgetattr(fd) if fd is not None else None

    try:
        _main()
    finally:
        if fd is not None and saved_tty is not None:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved_tty)


def _main():

    args = parse_args()

    if args.webhook:
        try:
            with open(args.webhook, "r", encoding="utf-8") as f:
                webhook_url = f.read().strip()
        except Exception as e:
            print(f"[!] Failed to read webhook file: {e}")
            sys.exit(1)
        init_webhook(webhook_url)

    input_path = Path(args.input_file)
    output_dir = Path(args.output_dir)

    # Validate input file path and load
    if not input_path.exists():
        print("[!] Input file does not exist")
        sys.exit(1)

    # Process config JSON file
    config = load_config(input_path)
    scans = config.get("scans", [])
    args = config.get("args")
    timeout = config.get("timeout")
    scan_name = config.get("name")

    # Validate output path
    output_path = output_dir / scan_name
    output_path.mkdir(parents=True, exist_ok=True)

    # Validate values from JSON (mostly to see if they exist)
    if not scans:
        print("[!] No scans defined in JSON")
        sys.exit(1)
    if not args:
        print("[!] No args defined in JSON")
        sys.exit(1)

    print(f"[+] Loaded {len(scans)} scans")
    print(f"[+] Output directory: {output_path}")

    results = []

    # We cap concurrency to a small, safe value.
    max_workers = min(4, len(scans))

    # ThreadPoolExecutor manages a pool of worker threads.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:

        # Submit each scan job to the thread pool.
        #
        # executor.submit():
        #   - Schedules the function to run in a worker thread
        #   - Returns a Future object
        #   - Does NOT block
        #
        # We collect all Future objects in a list
        # so we can track completion later.
        futures = [
            executor.submit(run_nmap, scan, args, timeout, output_path, scan_name)
            for scan in scans
        ]


        # as_completed() yields Future objects
        # as soon as they finish, regardless of order.
        for future in as_completed(futures):

            # Retrieve the return value of run_nmap().
            # If run_nmap raised an uncaught exception,
            # it will be re-raised here.
            result = future.result()

            results.append(result)

            # Report per-scan status
            if result["status"] == "success":
                print(f"[✓] {result['name']} completed")

            else:
                print(f"[✗] {result['name']} failed")
                print(result)
                send_discord(f"[✗] {result['name']} failed - " + result['error'])


    print("\n=== Summary ===")

    for r in results:
        print(f"{r['name']}: {r['status']}")

    print("[+] All scans finished")
    if any(r.get("has_findings") for r in results):
        send_discord("# Scans complete! Full Scans can be found here: http://10.62.128.2")


if __name__ == "__main__":
    main()
