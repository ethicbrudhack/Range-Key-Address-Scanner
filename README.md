🔎 Range Key Address Scanner — README (English)

⚠️ Educational / Research Use Only
This tool demonstrates how raw private keys map to cryptocurrency addresses across multiple chains (BTC, LTC, DOGE, BCH, DASH, ETH, SOL). It is intended only for learning, auditing, or legitimate recovery of your own wallets.
Do not use it to access wallets or funds that you do not own. The author is not responsible for misuse.

📘 Project Overview

This script iterates over a numeric range of 256-bit private keys (interpreted as big-endian integers), derives a set of addresses for common cryptocurrencies for each key, and checks whether any of those addresses exist in a local SQLite database (addresses table). If a match is found, it logs the corresponding private key and derived addresses to an output file.

This demonstrates low-level address generation (raw private-key → public key → address) for different address formats (legacy, compressed, Bech32, Ethereum, Solana, Bitcoin Cash formats, etc.), and how to efficiently search an address list for matches.

⚙️ Main features

Generates addresses from raw private key integers (big-endian 32 bytes).

Supports multiple address schemes:

Bitcoin: P2PKH (compressed & uncompressed), Bech32 (P2WPKH)

Litecoin: P2PKH, Bech32

Dogecoin, Dash: P2PKH

Bitcoin Cash: CashAddr and legacy formats

Ethereum: hex address (EIP-55 style via bip_utils)

Solana: ed25519-based public keys (via pynacl)

Reads a local SQLite database (read-only, shared cache) to check address existence.

Range-based scanning: centered at a HEX "center" value, scans CENTER ± SPAN.

Multi-threaded worker scanning with configurable number of threads.

Logs hits to an output file and prints generated addresses for each checked key.

🧩 Files & Configuration (important variables)

DB_PATH = "alladdresses3.DB" — path to the SQLite DB with an addresses table.

OUTPUT_FILE = "hits_range1.txt" — file where found hits are appended.

CENTER_HEX — 64-hex-character center private key (string); script validates/trims it.

SPAN — integer span added/subtracted to define the search interval.

MAX_WORKERS — number of parallel worker threads to split the range.

LOG_INTERVAL — how often (by derived-address count) an info log is printed.

🧠 How it works (high-level)

Key range calculation
The script converts CENTER_HEX to an integer CENTER_INT and computes START_INT = CENTER_INT - SPAN and END_INT = CENTER_INT + SPAN.

Address generation (generate_addresses)
For a given private-key integer:

Convert to 32-byte big-endian.

Create a secp256k1 private key and public key (using bip_utils helpers).

Produce multiple address formats (P2PKH uncompressed/compressed, P2WPKH Bech32, Litecoin, Dogecoin, Dash, BCH cash/legacy, ETH).

For Solana, convert the 32-byte seed to an ed25519 SigningKey and compute the base58 public key/address.

Address existence check (address_exists)
Open a read-only, shared SQLite connection and query SELECT 1 FROM addresses WHERE address = ? for each generated address.

Parallel scanning
The overall numeric range is split into MAX_WORKERS sub-ranges and each processed in a Python threading.Thread that iterates over private keys in that sub-range and runs process_key to generate and check addresses.

Logging hits
If any derived address is found in the DB, the script appends a block with the private key and all derived addresses (and private key formats) to OUTPUT_FILE.

🔧 Dependencies

Install dependencies with pip:

pip install bip-utils pynacl base58


bip-utils provides secp256k1 key handling and multiple address encoders used in the script.

▶️ Usage

Prepare a read-only SQLite database with a table addresses(address TEXT PRIMARY KEY) (or compatible schema).

Set configuration variables at the top of the script (or adjust them programmatically):

DB_PATH, OUTPUT_FILE, CENTER_HEX, SPAN, MAX_WORKERS, LOG_INTERVAL.

Run:

python3 range_scanner.py


The script prints progress to stdout and writes hits to hits_range1.txt.

🧪 Example scenario (educational)

You want to understand how a raw 32-byte private key maps to addresses in different ecosystems.

You create a small local database (alladdresses3.DB) containing a handful of test addresses you control.

Set CENTER_HEX to a test private key and a small SPAN, then run the script to observe address derivation and matching behavior.

⚠️ Security, legal & ethical notes

This tool derives private keys programmatically. Treat any keys generated or logged as sensitive secrets.

Do not run this against addresses or keys you do not control or have explicit permission to test. Attempting to access others' funds is illegal and unethical.

Keep your database and any output files secure — they can contain private key material if a hit occurs.

Consider running in a safe environment (air-gapped machine) if you are experimenting with private keys.

🛠️ Potential improvements / extension ideas

Add HMAC/entropy-based seeding to generate deterministic ranges.

Add a command-line interface (argparse) for configuring CENTER_HEX, SPAN, and MAX_WORKERS.

Add logging levels and optional rate-limited stdout to reduce console output.

Add an API to export hits to structured formats (CSV/JSON) with careful redaction options.

Add unit tests for address encoders and DB access.

License & Attribution

Use and distribute as you like, but please include an educational-use disclaimer. If you publish improvements, consider adding tests and safe-guarding features to avoid accidental exposure of private key material.

BTC donation address: bc1q4nyq7kr4nwq6zw35pg0zl0k9jmdmtmadlfvqhr
