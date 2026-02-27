#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
# import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
import shutil



def parse_args():
    parser = argparse.ArgumentParser(
        prog="Old Man Touchy (OMT)",
        description="Run multiple Nmap scans from JSON config",
        epilog="Example: OMT.py teams_short.json ./results"
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

    return parser.parse_args()


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    except Exception as e:
        print(f"[!] Failed to load JSON: {e}")
        sys.exit(1)


def run_nmap(scan, args, timeout, output_dir):
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
    name = scan.get("name", "scan")
    target = scan.get("target")
    # timeout = scan.get("timeout")


    # Target is mandatory — abort this scan if missing
    if not target:
        raise ValueError("Scan entry missing 'target' field")

    # Build per-scan output file path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{name}_{timestamp}"
    output_file = output_dir / filename


    # Construct the nmap command safely as a list
    # (avoids shell=True injection risks)
    cmd = [
        "nmap",
        *args.split(),     # Split argument string into flags
        target,
        "-oA",             # Normal all formats
        str(output_file)
    ]

    print(f"[+] Starting scan: {name}")
    print(f"    Command: {' '.join(cmd)}")

    try:
        # Execute the nmap process and wait for completion.
        # stdout/stderr are captured for error reporting.
        result = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            # timeout=int(timeout), # seconds
            bufsize=1
        )

        PROGRESS_PATTERNS = ("Stats:", "Timing:", "ETC:")

        for line in result.stdout:
            line = line.rstrip()
            if any(line.startswith(p) for p in PROGRESS_PATTERNS):
                print(f"    [{name}] {line}")
        returncode = result.wait()

        
        # Non-zero exit code indicates failure
        if result.returncode != 0:
            return {
                "name": name,
                "status": "error",
                "stderr": result.stderr
            }
        else:
            xml_file = output_file.with_suffix(".xml")
            backup_file = output_dir / f"{name}_latest.xml"
            shutil.copy2(xml_file, backup_file)
        

        # Successful scan
        return {
            "name": name,
            "status": "success",
            "output": str(output_file)
        }
    except subprocess.TimeoutExpired as e:
        return {
            "name": name,
            "status": "timeout",
            "error": f"Scan exceeded {timeout}s"
        }
    except Exception as e:
        # Catch unexpected runtime errors (OS issues, missing nmap, etc.)
        return {
            "name": name,
            "status": "exception",
            "error": str(e)
        }


def main():

    args = parse_args()

    input_path = Path(args.input_file)
    output_dir = Path(args.output_dir)

    # Validate paths
    if not input_path.exists():
        print("[!] Input file does not exist")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    config = load_config(input_path)

    scans = config.get("scans", [])
    args = config.get("args")
    timeout = config.get("timeout")

    if not scans:
        print("[!] No scans defined in JSON")
        sys.exit(1)
    if not args:
        print("[!] No args defined in JSON")
        sys.exit(1)

    print(f"[+] Loaded {len(scans)} scans")
    print(f"[+] Output directory: {output_dir}")

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
            executor.submit(run_nmap, scan, args, timeout, output_dir)
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


    print("\n=== Summary ===")

    for r in results:
        print(f"{r['name']}: {r['status']}")

    print("[+] All scans finished")


if __name__ == "__main__":
    main()
