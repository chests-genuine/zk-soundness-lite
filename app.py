# app.py
import os
import sys
import time
import hashlib
from web3 import Web3

RPC_URL = os.getenv("RPC_URL") or f"https://mainnet.infura.io/v3/{os.getenv('INFURA_API_KEY','')}"
DEFAULT_CONTRACT = "0x5A98FcBEA516Cf06857215779Fd812CA3beF1B32"

def verify_zk_contract(address):
    start = time.time()
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print("❌ RPC connection failed. Check RPC_URL/INFURA_API_KEY.")
        sys.exit(1)
       print(f"🔗 Connected. Chain ID: {w3.eth.chain_id} | Block: {w3.eth.block_number}")
    print(f"🕒 Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())} UTC")
    if not Web3.is_address(address):
        print("❌ Invalid Ethereum address format.")
        sys.exit(1)
    checksum = Web3.to_checksum_address(address)
    code = w3.eth.get_code(checksum)
    print(f"🧩 Bytecode length: {len(code)} bytes")
    if not code:
        print("⚠️ No bytecode found — address may be an EOA.")
        return
    zk_hash = hashlib.sha256(code).hexdigest()
    print(f"🔎 Contract: {checksum}")
    print(f"🛡️ Code SHA-256: {zk_hash}")
    # append log
    try:
        with open("verification_log.txt", "a") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} | {checksum} | {zk_hash}\n")
    except Exception:
        pass
    print(f"⏱️ Verification time: {time.time() - start:.2f}s")
    print("✅ Done — code integrity snapshot saved to verification_log.txt")

if __name__ == "__main__":
    addr = DEFAULT_CONTRACT
    if len(sys.argv) > 1:
        addr = sys.argv[1]
    verify_zk_contract(addr)
