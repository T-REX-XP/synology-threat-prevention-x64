#!/usr/bin/env python3
"""Convert a DB-IP Country Lite CSV gzip into the SPK's sorted range tables."""
import argparse
import csv
import gzip
import ipaddress
import struct


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source")
    parser.add_argument("output")
    args = parser.parse_args()
    tables = {4: bytearray(), 6: bytearray()}
    counts = {4: 0, 6: 0}
    last_end = {4: -1, 6: -1}
    with gzip.open(args.source, "rt", encoding="ascii", newline="") as source:
        for first, last, code in csv.reader(source):
            start = ipaddress.ip_address(first)
            end = ipaddress.ip_address(last)
            version = start.version
            if version != end.version or start > end or int(start) <= last_end[version]:
                raise ValueError("Invalid or overlapping range at " + first)
            last_end[version] = int(end)
            if len(code) != 2 or not code.isalpha() or not code.isupper():
                raise ValueError("Invalid country code at " + first)
            if code == "ZZ":
                continue
            tables[version].extend(start.packed + end.packed + code.encode("ascii"))
            counts[version] += 1
    if not all(counts.values()):
        raise ValueError("Expected data for both IPv4 and IPv6")
    with open(args.output, "wb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as packed:
            packed.write(struct.pack(">8sII", b"TPSGEO1\0", counts[4], counts[6]))
            packed.write(tables[4])
            packed.write(tables[6])


if __name__ == "__main__":
    main()
