#!/usr/bin/env python3
"""
VANET Blockchain Middleware
Watches /tmp/ for cycle data from fix.cc
Uploads flow rules to IPFS and anchors hash to Hyperledger Fabric
"""

import os
import json
import hashlib
import logging
import time
import socket
import glob
import sys
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Add current directory to path so imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import WATCH_DIR, LOG_FILE
from ipfs_client import upload_to_ipfs
from fabric_client import store_record
# ─── Verification Controller Config ──────────────────────────────────────────
VERIFY_SOCKET_PATH = "/tmp/vanet_verify.sock"
VC_THRESHOLD       = 0.75
# ─── Logging Setup ───────────────────────────────────────────────────────────
# Logs to both file and console simultaneously
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


# ─── Core Processing Pipeline ────────────────────────────────────────────────

def build_canonical_json(flow_rules: list) -> str:
    """
    Builds a canonical (deterministic) JSON string from flow rules.

    Why canonical?
    - Keys sorted alphabetically inside each flow rule dict
    - No extra whitespace (separators=(',', ':'))
    - Same flow rules ALWAYS produce identical byte sequence
    - Identical byte sequence = identical SHA-256 hash
    - This is critical for verification to work correctly

    Example output:
    '{"flow_rules":[{"delta":0.74,"flow_id":1,"from_node":5,
      "src":5,"to_node":12},...]}'
    """
    payload = {"flow_rules": flow_rules}

    return json.dumps(
        payload,
        sort_keys=True,        # sort keys alphabetically
        separators=(',', ':'), # no spaces after , or :
        ensure_ascii=True      # consistent encoding
    )


def compute_sha256(canonical_json: str) -> str:
    """
    Computes SHA-256 hash of the canonical JSON string.

    Returns lowercase hex string like:
    'e3b0c44298fc1c149afb4c8996fb92427ae41e4649b934ca495991b7852b855'

    Why SHA-256?
    - Standard cryptographic hash
    - 256-bit output = collision resistant
    - Built into Python hashlib (no external dependency)
    - Same input ALWAYS produces same output
    """
    return hashlib.sha256(
        canonical_json.encode("utf-8")
    ).hexdigest()


def verify_with_controllers(cycle_id: int) -> bool:
    """
    Connects to the verification socket in fix.cc.
    Sends cycle number, receives 4 independent scores from
    verification controllers, makes final PASS/FAIL decision.

    Returns True if PASS, False if FAIL.
    """
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(30)
        sock.connect(VERIFY_SOCKET_PATH)

        # Send verification request
        request = f"VERIFY:{cycle_id}\n"
        sock.sendall(request.encode("utf-8"))

        # Receive scores from all 4 verification controllers
        response = sock.recv(1024).decode("utf-8").strip()
        sock.close()

        # Expected format: "VC1:0.950000:VC2:0.930000:VC3:0.080000:VC4:0.910000"
        scores = {}
        parts = response.split(":")
        for i in range(0, len(parts) - 1, 2):
            vc_name  = parts[i]
            vc_score = float(parts[i + 1])
            scores[vc_name] = vc_score

        # Log each controller score individually
        for vc, score in scores.items():
            status = "PASS" if score >= VC_THRESHOLD else "FAIL"
            flag   = "⚠ SUSPICIOUS" if score < 0.3 else ""
            logger.info(
                f"Cycle {cycle_id}: {vc} score={score:.4f} → {status} {flag}"
            )

        # Middleware makes the final decision
        aggregate = sum(scores.values()) / len(scores)
        passed    = aggregate >= VC_THRESHOLD

        logger.info(
            f"Cycle {cycle_id}: aggregate={aggregate:.4f} "
            f"threshold={VC_THRESHOLD} → {'PASS ✓' if passed else 'FAIL ✗'}"
        )

        return passed

    except FileNotFoundError:
        logger.error(f"Cycle {cycle_id}: verification socket not found — "
                     f"is fix.cc running?")
        return False
    except socket.timeout:
        logger.error(f"Cycle {cycle_id}: verification socket timeout")
        return False
    except Exception as e:
        logger.error(f"Cycle {cycle_id}: verification error: {e}")
        return False

def process_cycle(cycle_id: int, json_file: str, sentinel_file: str):

    logger.info(f"{'='*50}")
    logger.info(f"Processing cycle {cycle_id}")

    try:
        if not os.path.exists(json_file):
            logger.error(f"JSON file not found: {json_file}")
            return

        with open(json_file, "r") as f:
            data = json.load(f)

        flow_rules = data.get("flow_rules", [])

        if not flow_rules:
            logger.warning(f"Cycle {cycle_id}: empty flow rules, skipping")
            return

        logger.info(f"Cycle {cycle_id}: read {len(flow_rules)} flow rules")

        canonical = build_canonical_json(flow_rules)
        logger.info(f"Cycle {cycle_id}: canonical JSON built ({len(canonical)} bytes)")
        sha256_hash = compute_sha256(canonical)
        logger.info(f"Cycle {cycle_id}: SHA-256 = {sha256_hash[:16]}...")

        # ── Verification Controllers ──────────────────────────────────────────
        # Before storing anything, verify flow rules with 4 independent
        # verification controllers running inside fix.cc
        logger.info(f"Cycle {cycle_id}: requesting verification...")
        verified = verify_with_controllers(cycle_id)

        if not verified:
            logger.warning(
                f"Cycle {cycle_id}: VERIFICATION FAILED — "
                f"possible malicious controller detected. "
                f"Skipping IPFS and blockchain storage."
            )
            return

        logger.info(f"Cycle {cycle_id}: verification PASSED — proceeding to storage")

        logger.info(f"Cycle {cycle_id}: uploading to IPFS...")
        cid = upload_to_ipfs(canonical)
        logger.info(f"Cycle {cycle_id}: IPFS CID = {cid}")

        logger.info(f"Cycle {cycle_id}: invoking Fabric chaincode...")

        sim_time = flow_rules[0].get("timestamp", 0.0) if flow_rules else 0.0
        cycle_id_from_data = flow_rules[0].get("cycle", cycle_id) if flow_rules else cycle_id

        success = store_record(
            cid=cid,
            sha256_hash=sha256_hash,
            cycle_id=cycle_id_from_data,
            sim_time=sim_time
        )

        if success:
            logger.info(
                f"Cycle {cycle_id} COMPLETE | "
                f"CID: {cid} | "
                f"Hash: {sha256_hash[:16]}... | "
                f"Fabric: OK"
            )
        else:
            logger.error(f"Cycle {cycle_id}: Fabric store FAILED")

    except Exception as e:
        logger.error(f"Cycle {cycle_id}: pipeline error: {e}")

    finally:
        for f in [json_file, sentinel_file]:
            try:
                if os.path.exists(f):
                    os.remove(f)
                    logger.debug(f"Cleaned up: {f}")
            except Exception as e:
                logger.warning(f"Could not remove {f}: {e}")

class CycleEventHandler(FileSystemEventHandler):
    """
    Watches /tmp/ for sentinel files created by fix.cc.

    fix.cc creates files like:
        /tmp/vanet_ready_7     ← sentinel (empty, signals cycle 7 ready)
        /tmp/vanet_cycle_7.json ← actual flow rules data

    When we detect vanet_ready_N we know vanet_cycle_N.json
    is fully written and ready to process.
    """

    def on_created(self, event):
        """Called automatically by watchdog when any file is created in /tmp/"""

        if event.is_directory:
            return

        filename = os.path.basename(event.src_path)

        # Only react to sentinel files matching pattern vanet_ready_N
        if not filename.startswith("vanet_ready_"):
            return

        # Extract cycle number from filename
        # e.g. "vanet_ready_7" → cycle_id = 7
        try:
            cycle_id = int(filename.replace("vanet_ready_", ""))
        except ValueError:
            logger.warning(f"Could not parse cycle id from: {filename}")
            return

        # Build paths for this cycle's files
        json_file     = os.path.join(WATCH_DIR, f"vanet_cycle_{cycle_id}.json")
        sentinel_file = event.src_path

        logger.info(f"Sentinel detected: {filename} → cycle {cycle_id}")

        # Small delay to ensure JSON file is fully flushed by fix.cc
        time.sleep(0.1)

        # Process this cycle
        process_cycle(cycle_id, json_file, sentinel_file)


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    logger.info("VANET Blockchain Middleware starting...")
    logger.info(f"Watching directory: {WATCH_DIR}")
    logger.info(f"Log file: {LOG_FILE}")

    # Set up watchdog observer
    # Observer runs in a background thread
    # CycleEventHandler.on_created() is called on each new file
    event_handler = CycleEventHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=False)
    observer.start()

    logger.info("Middleware ready — waiting for cycles from fix.cc...")

    try:
        # Keep main thread alive while observer runs in background
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Middleware stopping...")
        observer.stop()

    observer.join()
    logger.info("Middleware stopped")


if __name__ == "__main__":
    main()
