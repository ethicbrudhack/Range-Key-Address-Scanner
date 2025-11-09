import os
import sqlite3
import threading
import hashlib
import base58
from typing import Tuple, List

from bip_utils import (
    Secp256k1PrivateKey,
    P2PKHAddrEncoder,
    P2WPKHAddrEncoder,
    BchP2PKHAddrEncoder,
    EthAddrEncoder,
)
import nacl.signing  # Solana

# --------------------------------------------------------
#                 USTAWIENIA GLOBALNE
# --------------------------------------------------------
DB_PATH      = "alladdresses3.DB"
OUTPUT_FILE  = "hits_range1.txt"
CENTER_HEX   = "0000000000000000000000000000000000000000000004c5ce114686a1336e07"
SPAN         = 39614081257132168796771975167
MAX_WORKERS  = 4
LOG_INTERVAL = 100_000

# Trim and validate CENTER_HEX
CENTER_HEX = CENTER_HEX.strip()
if len(CENTER_HEX) < 64:
    raise ValueError(f"CENTER_HEX must be 64 hex chars, got {len(CENTER_HEX)}")
if len(CENTER_HEX) > 64:
    CENTER_HEX = CENTER_HEX[-64:]

# --------------------------------------------------------
#               KONWERSJA KLUCZA
# --------------------------------------------------------
def priv_to_wif(priv_hex: str, compressed: bool = True) -> str:
    data = bytes.fromhex(priv_hex)
    prefix = b"\x80" + data + (b"\x01" if compressed else b"")
    checksum = hashlib.sha256(hashlib.sha256(prefix).digest()).digest()[:4]
    return base58.b58encode(prefix + checksum).decode()

# --------------------------------------------------------
#               SOLANA ADDR
# --------------------------------------------------------
def solana_addr(priv_int: int) -> Tuple[str, str]:
    seed = priv_int.to_bytes(32, "big")
    signer = nacl.signing.SigningKey(seed)
    addr = base58.b58encode(signer.verify_key.encode()).decode()
    return addr, seed.hex()

# --------------------------------------------------------
#           GENEROWANIE WSZYSTKICH ADRESÓW
# --------------------------------------------------------
def generate_addresses(priv_int: int) -> List[Tuple[str, str, str]]:
    priv_bytes = priv_int.to_bytes(32, 'big')
    priv_hex = priv_bytes.hex()
    secp_priv = Secp256k1PrivateKey.FromBytes(priv_bytes)
    pub_key = secp_priv.PublicKey()
    out: List[Tuple[str, str, str]] = []

    # BTC-P2PKH Uncompressed
    pub_uncomp = pub_key.RawUncompressed().ToBytes()[1:]  # drop 0x04
    h160 = hashlib.new('ripemd160', hashlib.sha256(pub_uncomp).digest()).digest()
    payload = b"\x00" + h160
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    addr_uncomp = base58.b58encode(payload + checksum).decode()
    out.append(("BTC-P2PKH-Uncompressed", addr_uncomp, priv_to_wif(priv_hex, compressed=False)))

    # BTC-P2PKH Compressed
    addr_comp = P2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x00")
    out.append(("BTC-P2PKH-Compressed", addr_comp, priv_to_wif(priv_hex, compressed=True)))

    # BTC Bech32
    segwit = P2WPKHAddrEncoder.EncodeKey(pub_key, hrp="bc")
    out.append(("BTC-Bech32", segwit, priv_to_wif(priv_hex, compressed=True)))

    # LTC
    ltc_p2pkh = P2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x30")
    ltc_bech = P2WPKHAddrEncoder.EncodeKey(pub_key, hrp="ltc")
    out.append(("LTC-P2PKH", ltc_p2pkh, priv_to_wif(priv_hex)))
    out.append(("LTC-Bech32", ltc_bech, priv_to_wif(priv_hex)))

    # DOGE
    doge = P2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x1e")
    out.append(("DOGE", doge, priv_to_wif(priv_hex)))

    # DASH
    dash = P2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x4c")
    out.append(("DASH", dash, priv_to_wif(priv_hex)))

    # BCH Cash + Legacy
    cash = BchP2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x00", hrp="bitcoincash").split(':')[-1]
    legacy = P2PKHAddrEncoder.EncodeKey(pub_key, net_ver=b"\x00")
    out.append(("BCH-Cash", cash, priv_to_wif(priv_hex)))
    out.append(("BCH-Legacy", legacy, priv_to_wif(priv_hex)))

    # ETH
    eth = EthAddrEncoder.EncodeKey(pub_key)
    out.append(("ETH", eth, priv_hex))

    # SOL
    sol_addr, sol_priv = solana_addr(priv_int)
    out.append(("SOL", sol_addr, sol_priv))

    return out

# --------------------------------------------------------
#                  BAZA DANYCH
# --------------------------------------------------------
def db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro&cache=shared", uri=True, check_same_thread=False)
    conn.isolation_level = None
    return conn


def address_exists(conn: sqlite3.Connection, address: str) -> bool:
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM addresses WHERE address = ? LIMIT 1", (address,))
    return cur.fetchone() is not None

# --------------------------------------------------------
#               PRZETWARZANIE KLUCZA
# --------------------------------------------------------
checked = 0
lock = threading.Lock()

CENTER_INT = int(CENTER_HEX, 16)
START_INT = CENTER_INT - SPAN
END_INT = CENTER_INT + SPAN

# --------------------------------------------------------
def process_key(priv_int: int, conn: sqlite3.Connection):
    global checked
    entries = generate_addresses(priv_int)
    hits = [addr for _, addr, _ in entries if address_exists(conn, addr)]

    print(f"[KEY] {priv_int}")
    for coin, addr, priv in entries:
        print(f"[GEN] {coin} | {addr} | priv: {priv}")

    if hits:
        print(f"[HIT] {priv_int} -> {hits}")
        with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
            f.write(f"=== HIT for {priv_int} ===\n")
            for coin, addr, priv in entries:
                f.write(f"{coin}: {addr}  priv: {priv}\n")
            f.write("-------------------------\n")

    with lock:
        checked += len(entries)
        if checked % LOG_INTERVAL == 0:
            print(f"[INFO] Sprawdzono {checked} adresów")

# --------------------------------------------------------
def search_range(start: int, end: int):
    conn = db_connection()
    for priv in range(start, end + 1):
        process_key(priv, conn)

# --------------------------------------------------------
def main():
    if not os.path.exists(DB_PATH):
        print(f"Brak bazy: {DB_PATH}")
        return

    print(f"Zakres: {hex(START_INT)}…{hex(END_INT)} (center={CENTER_HEX})")

    conn = db_connection()
    process_key(CENTER_INT, conn)
    conn.close()

    threads: List[threading.Thread] = []
    step = (END_INT - START_INT) // MAX_WORKERS
    for i in range(MAX_WORKERS):
        s = START_INT + i * step
        e = START_INT + (i + 1) * step if i < MAX_WORKERS - 1 else END_INT
        t = threading.Thread(target=search_range, args=(s, e))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print(f"[ZAKOŃCZONE] Sprawdzono {checked} adresów.")

if __name__ == "__main__":
    main()
