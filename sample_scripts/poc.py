#!/usr/bin/env python3

import os
import json
import hmac
import base64
import requests
import urllib.parse

from hashlib import md5, sha1
from dotenv import load_dotenv

load_dotenv()

# Load environment variables
TAPO_BUILD_ANDROID_ID = os.environ["TAPO_BUILD_ANDROID_ID"]
TAPO_SECRET_KEY = os.environ["TAPO_SECRET_KEY"]
TAPO_ACCESS_KEY = os.environ["TAPO_ACCESS_KEY"]
TAPO_CLOUD_USERNAME = os.environ["TAPO_CLOUD_USERNAME"]
TAPO_CLOUD_PASSWORD = os.environ["TAPO_CLOUD_PASSWORD"]

# Disable warnings from requests library
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

parameters = {
    "host": "n-euw1-wap.i.tplinkcloud.com",
    "payload": {
        "cloudUserName": TAPO_CLOUD_USERNAME,
        "supportBindAccount": "false"
    },
    "timestamp": "9999999999",
    "nonce": "2fc24cfb-49e4-49a4-a634-27d905c565f9",
    "path": "/api/v2/account/getAccountInfo",
    "urlParams": {
        "appName": "TP-Link_Tapo_Android",
        "appVer": "3.19.607",
        "netType": "wifi",
        "termID": "",
        "ospf": "Android 16",
        "brand": "TPLINK",
        "locale": "en_US",
        "model": "Redmi Note 9",
        "termName": "Xiaomi Redmi Note 9",
        "termMeta": "1",
        "token": ""
    },
    "buildHeader": "35",
    "buildInfo": {
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
    },
    "buildAndroidId": f"{os.environ['TAPO_BUILD_ANDROID_ID']}",
    "secretKey": f"{os.environ['TAPO_SECRET_KEY']}",
    "accessKey": f"{os.environ['TAPO_ACCESS_KEY']}"
}

def getToken():
    """
    Generate TP-Link access token
    Originally described by Art Chaidarun: https://chaidarun.com/tp-link-api
    """
    termId = parameters["urlParams"]["termID"]

    url = "https://wap.tplinkcloud.com"

    headers = {
        "Content-Type": "application/json"
    }

    payload = {
        "method": "login",
        "params": {
            "appType": "TP-Link_Tapo_Android",
            "cloudUserName": f"{os.environ['TAPO_CLOUD_USERNAME']}",
            "cloudPassword": f"{os.environ['TAPO_CLOUD_PASSWORD']}",
            "terminalUUID": termId
        }
    }

    payload = json.dumps(payload)
    payload = json.loads(payload)

    response = requests.post(url, headers=headers, json=payload, verify=False)
    response_json = json.loads(response.content)
    
    return response_json["result"]["token"]

def encodePayload():
    payload = json.dumps(parameters["payload"]).encode(encoding = 'UTF-8', errors = 'strict')
    bodyMD5 = md5(payload).digest()
    bodyBase64 = base64.b64encode(bodyMD5).decode('UTF-8')

    return bodyBase64

def computeSignature():
    encodedPayload = encodePayload()
    secretKeyBytes = bytes(parameters["secretKey"], 'utf-8')

    fingerprint = encodedPayload + "\n" + parameters["timestamp"] + "\n" + parameters["nonce"] + "\n" + parameters["path"]
    fingerprint = bytes(fingerprint, "utf-8")

    signature = hmac.new(secretKeyBytes, fingerprint, sha1).digest().hex()

    return signature

def computeTermId():
    """Compute a valid termID URL parameter from Android build info"""
    fingerprint = parameters["buildHeader"]
    for value in parameters["buildInfo"].values():
        last_digit = len(value) % 10
        fingerprint += str(last_digit)
    fingerprint += parameters["buildAndroidId"]
    fingerprint = fingerprint.encode(encoding = 'UTF-8', errors = 'strict')

    termId = md5(fingerprint).hexdigest().upper()

    return termId

def buildUrl():
    """Build a valid URL (that is URL-encoded) for TP-Link API request"""
    # Update empty parameters with generated data
    parameters["urlParams"]["termID"] = computeTermId()
    parameters["urlParams"]["token"] = getToken()

    host = parameters["host"]
    path = parameters["path"]
    params = urllib.parse.urlencode(parameters["urlParams"])

    url = f"https://{host}{path}?{params}"

    return url

def createRequest():
    """Craft HTTP request to TP-Link API"""
    encodedPayload = encodePayload()
    signature = computeSignature()

    timestamp = parameters["timestamp"]
    nonce = parameters["nonce"]
    accessKey = parameters["accessKey"]
    payload = json.dumps(parameters["payload"])
    host = parameters["host"]
    url = buildUrl()

    headers = {
        "Content-MD5": encodedPayload,
        "X-Authorization": f"Timestamp={timestamp}, Nonce={nonce}, AccessKey={accessKey}, Signature={signature}",
        "Content-Type": "application/json;charset=UTF-8",
        "Content-Length": str(len(payload.encode("utf-8"))),
        "Host": host,
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "User-Agent": "okhttp/4.11.0"
    }

    response = requests.post(url, headers=headers, data=payload, verify=False)

    return url, headers, response.content

def dumpReplayData(url, payload, headers, response):
    """Dump replay data in JSON format"""
    payload = json.dumps(payload)

    replay_data = {
        "url": url,
        "payload": json.loads(payload),
        "headers": headers,
        "response": json.loads(response.decode('utf-8'))
    }

    with open("replay_data.json", "w") as file:
        json.dump(replay_data, file, indent=4)
        print("Replay data written to replay_data.json")

def main():
    url, headers, response = createRequest()

    try:
        dumpReplayData(url, parameters["payload"], headers, response)
    except TypeError as e:
        print(f"Error formatting JSON: {e}")

if __name__ == "__main__":
    main()
