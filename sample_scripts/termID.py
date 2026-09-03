#!/usr/bin/env python3

from hashlib import md5

def device_information():
    """Android device information, used to build termID"""
    header = "35"

    build_info = {
        "board": "mt6768",
        "brand": "Redmi",
        "cpu_abi": "arm64-v8a",
        "device": "merlinx",
        "display": "lineage_merlinx-userdebug 16 BP2A.250605.031.A2 eng.androi.20250916.075845 test-keys",
        "host": "r-cca484a1fca13862-f3pp",
        "id": "BP2A.250605.031.A2",
        "manufacturer": "Xiaomi",
        "model": "Redmi Note 9",
        "product": "lineage_merlinx",
        "tags": "release-keys",
        "type": "user",
        "user": "android-build"
    }

    android_id = "988583252ee0bd24"

    return header, build_info, android_id

def main():
    fingerprint, build_info, android_id = device_information()

    for value in build_info.values():
        last_digit = len(value) % 10
        fingerprint += str(last_digit)

    fingerprint += android_id
    fingerprint = fingerprint.encode(encoding = 'UTF-8', errors = 'strict')

    termID = md5(fingerprint).hexdigest().upper()
    print(f"TermID: {termID}")

if __name__ == "__main__":
    main()
