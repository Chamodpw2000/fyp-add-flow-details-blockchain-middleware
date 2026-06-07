import requests
import logging
import time
from config import IPFS_API_ADD, IPFS_API_PIN, IPFS_RETRIES

logger = logging.getLogger(__name__)


def upload_to_ipfs(canonical_json: str) -> str:
    """
    Uploads canonical JSON string to local IPFS node.
    Returns the CID string on success.
    Raises Exception on failure after retries.

    How it works:
    - IPFS /api/v0/add accepts multipart file upload
    - We send the JSON bytes as a file named 'flowrules.json'
    - IPFS computes the CID from content and stores it
    - We pin it so garbage collection never removes it
    """

    json_bytes = canonical_json.encode("utf-8")

    for attempt in range(1, IPFS_RETRIES + 1):
        try:
            # ── Upload ──────────────────────────────────────
            # 'files' param sends as multipart/form-data
            # IPFS requires this format for /api/v0/add
            response = requests.post(
                IPFS_API_ADD,
                files={"file": ("flowrules.json", json_bytes, "application/json")},
                timeout=30
            )

            if response.status_code != 200:
                raise Exception(f"IPFS add failed: HTTP {response.status_code}")

            # Response looks like:
            # {"Name":"flowrules.json","Hash":"bafyreig3...","Size":"312"}
            cid = response.json()["Hash"]
            logger.info(f"IPFS upload success | CID: {cid}")

            # ── Pin ─────────────────────────────────────────
            # Pinning tells IPFS: never garbage collect this
            # Without pinning, IPFS may delete it during cleanup
            pin_response = requests.post(
                IPFS_API_PIN,
                params={"arg": cid},
                timeout=30
            )

            if pin_response.status_code != 200:
                # Pin failed but upload succeeded
                # Log warning but still return CID
                logger.warning(f"IPFS pin failed for CID {cid} "
                               f"but upload succeeded")

            return cid

        except Exception as e:
            logger.error(f"IPFS attempt {attempt}/{IPFS_RETRIES} "
                         f"failed: {e}")
            if attempt < IPFS_RETRIES:
                time.sleep(2)  # wait 2 seconds before retry

    raise Exception(f"IPFS upload failed after {IPFS_RETRIES} attempts")


def verify_ipfs_content(cid: str) -> bool:
    """
    Verifies that a CID is accessible from local node.
    Used during testing to confirm upload worked.
    """
    try:
        response = requests.post(
            "http://127.0.0.1:5001/api/v0/cat",
            params={"arg": cid},
            timeout=10
        )
        return response.status_code == 200
    except Exception:
        return False
