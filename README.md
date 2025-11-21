# README.md
# repo: zk-soundness-lite.

Overview
This small repository provides a lightweight utility to snapshot and verify on-chain contract bytecode integrity (useful when auditing ZK-related contracts or comparing deployments across networks). Inspired by projects in the web3 / zk space (Aztec, Zama, soundness tooling).

Files
- `app.py` — main script (Python, uses web3.py)
- `verification_log.txt` — created after first run (appends timestamp, address, sha256)

Requirements
- Python 3.10+
- Install dependency:
  pip install web3

Configuration
- Provide an RPC endpoint via environment variable `RPC_URL`, or set `INFURA_API_KEY` and the script will build an Infura mainnet URL.
  export RPC_URL="https://your-rpc.node"
  or
  export INFURA_API_KEY="your_infura_project_id"

Usage
- Run with default example contract:
  python3 app.py
- Run for a specific address:
  python3 app.py 0xYourContractAddress

What the script does (expected output)
- Connects to the configured RPC and prints chain id and current block.
- Validates the provided address format.
- Fetches on-chain bytecode and prints its length.
- Computes and prints the SHA-256 hash of the bytecode.
- Appends a line to `verification_log.txt` with timestamp | address | hash.
Example output:
🔗 Connected. Chain ID: 1 | Block: 19412345
🧩 Bytecode length: 1024 bytes
🔎 Contract: 0x5A98Fc...
🛡️ Code SHA-256: e2c7a9...
⏱️ Verification time: 0.42s
✅ Done — code integrity snapshot saved to verification_log.txt

Notes & next steps
- Swap RPC_URL to point at Aztec / Zama or any zk-enabled node to inspect contracts on those networks.
- For reproducible audits, compare `verification_log.txt` entries across machines or CI; consider storing canonical hashes for automated checks.
- For production, keep RPC keys secret and consider HSM/secret managers and stricter logging.
- You can expand the script to compare against an expected hash, fetch ABI from Etherscan-like services, or emit Merkle proofs for multi-contract snapshots.
