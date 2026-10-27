"""Compare SHA-256 digests and export reproducible classroom data."""
import argparse
import csv
from pathlib import Path
from .crypto_examples import sha256_text


def compare(inputs):
    if not inputs:
        raise ValueError("Supply at least one input")
    baseline = sha256_text(inputs[0])
    rows = []
    for text in inputs:
        digest = sha256_text(text)
        bits = (int(baseline, 16) ^ int(digest, 16)).bit_count()
        rows.append({"input": text, "sha256": digest,
                     "changed_bits_vs_first": bits, "total_bits": 256,
                     "changed_percent": round(bits / 256 * 100, 2)})
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="*", default=["Hello", "hello", "Hello!", "Hello"])
    parser.add_argument("--out", default="results/hash_comparison.csv")
    args = parser.parse_args()
    rows = compare(args.inputs)
    path = Path(args.out)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    for row in rows:
        print(row)
    print("Saved:", path)


if __name__ == "__main__":
    main()
