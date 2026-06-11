"""Download a pinned ATT&CK Enterprise STIX bundle into data/attack/.

    python scripts/fetch_attack.py            # default pinned version
    python scripts/fetch_attack.py 17.1       # a specific version

Pulls from the official mitre-attack/attack-stix-data repo. The file is large (~50MB) and is
gitignored — re-ingestion on an ATT&CK release (~2x/yr) is the KG-ingestion owner's job (RACI,
05 §2.6). `ReferenceIndex.load_default()` then picks up the newest bundle automatically.
"""

from __future__ import annotations

import pathlib
import sys
import urllib.request

DEFAULT_VERSION = "18.0"
BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack"
DATA_DIR = pathlib.Path(__file__).resolve().parents[1] / "data" / "attack"


def main() -> None:
    version = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_VERSION
    url = f"{BASE}/enterprise-attack-{version}.json"
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    dest = DATA_DIR / f"enterprise-attack-{version}.json"
    print(f"Downloading {url}\n      -> {dest}")
    urllib.request.urlretrieve(url, dest)
    size_mb = dest.stat().st_size / 1_000_000
    print(f"Done ({size_mb:.1f} MB). ReferenceIndex.load_default() will now use it.")


if __name__ == "__main__":
    main()
