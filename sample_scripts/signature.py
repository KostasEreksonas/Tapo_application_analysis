#!/usr/bin/env python3

import hmac
import base64

from hashlib import md5, sha1

def inputArguments():
    payload = bytearray("<put-your-payload-here>", "utf-8")
    timestamp = "<timestamp-here>"
    nonce = "<nonce-here>"
    path = "<encoded-path>"

    return payload, timestamp, nonce, path

def encodePayload(payload):
    bodyMD5 = md5(payload).digest()
    return base64.b64encode(bodyMD5)

def computeSignature(encodedPayload, timestamp, nonce, path):
    secretKey = "<secret-key>"
    secretKeyBytes = bytes(secretKey, 'utf-8')

    signature = encodedPayload.decode("utf-8") + "\n" + str(timestamp) + "\n" + nonce + "\n" + path
    signature = bytes(signature, "utf-8")

    HmacSHA1 = hmac.new(secretKeyBytes, signature, sha1).digest().hex()

    return HmacSHA1

def main():
    payload, timestamp, nonce, path = inputArguments()
    encodedPayload = encodePayload(payload)
    signature = computeSignature(encodedPayload, timestamp, nonce, path)
    print(f"Input Parameters:\n\tPayload: {payload}\n\tEncoded Payload: {encodedPayload}\n\tTimestamp: {timestamp}\n\tNonce: {nonce}\n\tPath: {path}\n\tSignature: {signature}")

if __name__ == "__main__":
    main()
