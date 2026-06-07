import subprocess
import os
import logging
from config import (
    BIN_DIR, CFG_DIR, CHANNEL_NAME, CHAINCODE_NAME,
    PEER_ORG1, PEER_ORG2, ORDERER,
    TLS_CERT_ORG1, TLS_CERT_ORG2, MSP_PATH_ORG1, ORDERER_CA
)

logger = logging.getLogger(__name__)


def _get_fabric_env() -> dict:
    """
    Builds the environment variables needed for peer CLI commands.
    These are the same exports you ran manually in the terminal.
    We set them programmatically so subprocess inherits them.
    """
    env = os.environ.copy()
    env.update({
        "PATH":                      f"{BIN_DIR}:{env.get('PATH', '')}",
        "FABRIC_CFG_PATH":           CFG_DIR,
        "CORE_PEER_TLS_ENABLED":     "true",
        "CORE_PEER_LOCALMSPID":      "Org1MSP",
        "CORE_PEER_ADDRESS":         PEER_ORG1,
        "CORE_PEER_TLS_ROOTCERT_FILE": TLS_CERT_ORG1,
        "CORE_PEER_MSPCONFIGPATH":   MSP_PATH_ORG1,
    })
    return env


def store_record(cid: str, sha256_hash: str,
                 cycle_id: int, sim_time: float) -> bool:
    """
    Invokes StoreRecord chaincode function on mychannel.
    Returns True on success, False on failure.

    Builds and runs this CLI command programmatically:
        peer chaincode invoke
            -o localhost:7050
            --tls --cafile <orderer_ca>
            -C mychannel -n flowrecord
            --peerAddresses localhost:7051 --tlsRootCertFiles <org1_tls>
            --peerAddresses localhost:9051 --tlsRootCertFiles <org2_tls>
            -c '{"function":"StoreRecord","Args":[...]}'
    """

    # Build the invoke payload
    # Note: all Args must be strings in Fabric CLI
    args_json = (
        f'{{"function":"StoreRecord",'
        f'"Args":["{cid}","{sha256_hash}",'
        f'"{cycle_id}","{sim_time}"]}}'
    )

    # Build the full peer command as a list
    # Using list form (not shell string) is safer — no injection risk
    cmd = [
        "peer", "chaincode", "invoke",
        "-o", ORDERER,
        "--ordererTLSHostnameOverride", "orderer.example.com",
        "--tls",
        "--cafile", ORDERER_CA,
        "-C", CHANNEL_NAME,
        "-n", CHAINCODE_NAME,
        "--peerAddresses", PEER_ORG1,
        "--tlsRootCertFiles", TLS_CERT_ORG1,
        "--peerAddresses", PEER_ORG2,
        "--tlsRootCertFiles", TLS_CERT_ORG2,
        "-c", args_json
    ]

    try:
        result = subprocess.run(
            cmd,
            env=_get_fabric_env(),
            capture_output=True,
            text=True,
            timeout=30
        )

        # peer chaincode invoke writes result to stderr (Fabric behavior)
        output = result.stderr + result.stdout

        if result.returncode == 0 and "status:200" in output:
            logger.info(f"Fabric StoreRecord success | "
                        f"CID: {cid} | Cycle: {cycle_id}")
            return True
        else:
            logger.error(f"Fabric StoreRecord failed | "
                         f"returncode: {result.returncode} | "
                         f"output: {output}")
            return False

    except subprocess.TimeoutExpired:
        logger.error(f"Fabric invoke timeout for cycle {cycle_id}")
        return False
    except Exception as e:
        logger.error(f"Fabric invoke exception: {e}")
        return False


def get_record(cid: str) -> dict:
    """
    Queries GetRecord chaincode function.
    Returns the record as a dict, or None if not found.
    Used for verification.
    """

    args_json = f'{{"function":"GetRecord","Args":["{cid}"]}}'

    cmd = [
        "peer", "chaincode", "query",
        "-C", CHANNEL_NAME,
        "-n", CHAINCODE_NAME,
        "-c", args_json
    ]

    try:
        result = subprocess.run(
            cmd,
            env=_get_fabric_env(),
            capture_output=True,
            text=True,
            timeout=15
        )

        if result.returncode == 0:
            import json
            return json.loads(result.stdout.strip())
        else:
            logger.error(f"GetRecord failed: {result.stderr}")
            return None

    except Exception as e:
        logger.error(f"GetRecord exception: {e}")
        return None
