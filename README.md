# TP-Link Tapo Android Application Security Analysis

Analyzing security methods of TP-Link Tapo Android application for personal account and data protection.

Table of Contents
=================
* [Prerequisites](#prerequisites)
* [Initial Analysis](#initial-analysis)
* [Static Analysis](#static-analysis)
    * [Pulling Application Files](#pulling-application-files)
    * [Code Analysis With JADX](#code-analysis-with-jadx)
    * [Signature Algorithm](#signature-algorithm)
* [Dynamic Analysis](#dynamic-analysis)
    * [Frida Hook for Intercepting HTTP Request Signatures](#frida-hook-for-intercepting-http-request-signatures)
* [Python Implementation](#python-implementation)

# Prerequisites

***DISCLAIMER:*** This research has been conducted on the devices that I own (TP-Link Tapo C100 + smartphone) and my personal TP-Link account. All the intercepted traffic touches only my own account/device pairing. The goal of this research was to understand how did the authentication mechanism protect my personal account and data.

Tools that were used (JADX for static code analysis and Frida for dynamic analysis at runtime):

1. JADX decompiler, installed on host machine.
2. `frida-server`, installed on my rooted Android device ([my custom helper script can be found by following this link](https://github.com/KostasEreksonas/android_analysis/blob/main/scripts/install_frida)).
3. Frida client installed on a host machine via a package manager (e.g. `uv`).

# Initial Analysis

For analyzing the application (and cryptography research in general), I created a Javascript Frida hook - [which can be found by following this link to the project's Github repository](https://github.com/KostasEreksonas/android_analysis/blob/main/hooks/crypto_discovery.js) - that overloads multiple methods in Base64, Cipher and Mac Java classes, logging relevant cryptographic data and payload preview (both plaintext and encrypted/encoded) in a JSON format. Overloaded methods include:

1. Cipher:
    * getInstance()
    * init()
    * update()
    * doFinal()
2. Mac:
    * getInstance()
    * init()
    * update()
    * doFinal()
3. Base64:
    * encode()
    * encodeToString()
    * decode()

During cryptographic data collection (spawning Tapo Android application with the aforementioned Frida hook attached), the following Mac operation was captured:

```json
{
  "objectId": "Mac-164946758",
  "timestamp": 1787406387352,
  "instanceOverload": "1. [Mac.getInstance(java.lang.String) -> static Mac]",
  "transformation": "HmacSHA1",
  "algorithm": "HmacSHA1",
  "runtimeClass": "javax.crypto.Mac",
  "providerName": "AndroidOpenSSL",
  "providerVersion": 1,
  "providerInfo": "Android's OpenSSL-backed security provider",
  "providerClass": "com.android.org.conscrypt.OpenSSLProvider",
  "updateCount": 1,
  "updates": [
    "46365a47373637556462796750435a624855765546673d3d0a393939393939393939390a36613963616364352d623339 ... [56 more bytes]"
  ],
  "initOverload": "1. [Mac.init(Key key) -> void]",
  "macLength": 20,
  "keyClass": "javax.crypto.spec.SecretKeySpec",
  "keyAlgorithm": "HmacSHA1",
  "keyFormat": "RAW",
  "keyBytesString": "6ed7d97f3e73467f8a5bab90b577ba4c",
  "keyBytesFingerprint": "1eb62507:32",
  "updateOverload": "1. [Mac.update(byte[] input) -> void]",
  "finalOverload": "1. [Mac.doFinal() -> byte[]]",
  "bytesWritten": 20,
  "output": "41d55eea6002588e6ff213340d441e11a9ea2c85",
  "outputFingerprint": "f782e0dd:20",
}
```

The interesting value here is `6ed7d97f3e73467f8a5bab90b577ba4c` - [as per ad1s0n's dev.to article](https://dev.to/ad1s0n/reverse-engineering-tp-link-tapos-rest-api-part-1-4g6), this HMAC secret key is hardcoded into the Tapo application (later this was confirmed by doing static analysis with JADX).

# Static Analysis

For static analysis, the targeted application needs to be pulled the Android device via `adb`.

## Pulling Application Files

1. List relevant packages:

```sh
adb shell pm list packages | grep <package-name>
```

2. Get full path name for the package with `adb shell pm path <package-name>`:

```
package:/data/app/~~s-<base64-string>/<package-name>-n_K_-<base64-string>/base.apk
package:/data/app/~~s-<base64-string>/<package-name>-n_K_-<base64-string>/split_asset_pack.apk
package:/data/app/~~s-<base64-string>/<package-name>-n_K_-<base64-string>/split_config.arm64_v8a.apk
package:/data/app/~~s-<base64-string>/<package-name>-n_K_-<base64-string>/split_config.en.apk
package:/data/app/~~s-<base64-string>/<package-name>-n_K_-<base64-string>/split_config.xxhdpi.apk
```

Core application logic is stored in `base.apk` with assets and configs stored in separate .apk files. For the purposes of current research, only the base application file was analyzed.

3. Pull the `base.apk` to host machine:

```sh
adb pull /data/app/~~s-<base64-string>/<package-name>-n_K_-<base64-string>/base.apk
```

4. [A shell script that automates package pulling process can be found by following this link](https://github.com/KostasEreksonas/android_analysis/blob/main/scripts/pull_application).

## Code Analysis With JADX

1. Load `base.apk` into JADX.

2. Search for the hardcoded HMAC key:

![Hardcoded HMAC key](images/1.png)

3. Full function with the hardcoded HMAC key:

![Full function with the hardcoded HMAC key](images/2.png)

4. Search for `m235933h()` function and select `addInterceptor`:

![Interceptor function](images/3.png)

5. Following the `C63377r()` object declaration shows decompiled methods where actual signature building happens:

![Signature building logic](images/4.png)

One additional thing to note is that `C63377r(String str, String str2)` takes 2 arguments:

1. First argument is ***access key*** - separate hardcoded value, used as a part of X-Authorization header in a HTTP request (example of which is provided in a [Signature Algorithm](#signature-algorithm) section).
2. Second argument is ***secret key*** - already described in [initial analysis](#initial-analysis) section, used as a key for HTTP request signature derivation.

***Note:*** Short class and method identifiers - ids (e.g. l7.r) that JADX renames from - are obfuscated representations of real class/method names and change with every application version. For this analysis, version 3.19.607 of TP-Link Tapo application was used.

## Signature Algorithm

1. Signature function takes four parameters as input:
    * MD5 hash of a requestBody (usually a JSON payload) that is Base64 encoded.
    * Timestamp (equals `9999999999`, hardcoded into the Android application).
    * Random nonce, generated with `UUID.randomUUID().toString()`.
    * Path to the requested API endpoint.
2. Parameters are concatenated into a single line and separated by a newline symbol (\n).
3. Signature function outputs HmacSHA1 hash, derived from the mixture of concatenated parameter string and a secret key that is hardcoded into the Android application.

On a high level, the signature derivation scheme can look as follows:

![Signature derivation scheme](images/5.png)

For example, if the following HTTP request is captured:

```http
POST /api/v2/account/getMFAFeatureStatus?appName=TP-Link_Tapo_Android&appVer=3.19.607&netType=wifi&termID=<term-id>&ospf=Android%2012&brand=TPLINK&locale=en_GB&model=<smartphone-model>&termName=<smartphone-term-name>&termMeta=1&token=<token> HTTP/1.1
Content-MD5: mZFLkyvTelC5g8XnyQrpOw==
X-Authorization: Timestamp=9999999999,
                 Nonce=d78ef6b9-d1cb-4610-8219-589833f0c1f8,
                 AccessKey=<access-key>,
                 Signature=a7356d83df620ee3fa326151b212883c458e4d33
Content-Type: application/json; charset=utf-8
Content-Length: 2
Host: n-euw1-wap.i.tplinkcloud.com
Connection: Keep-Alive
Accept-Encoding: gzip
User-Agent: okhttp/4.11.0

{}
```

Then conceptually, the signature is built in the following way:

```python
signature = hmac.new(secretKey, str(Content-MD5 + "\n" + Timestamp + "\n" + Nonce + "\n" + "/api/v2/account/getMFAFeatureStatus"), sha1).hexdigest()
```

# Dynamic Analysis

Dynamic analysis allows to intercept and analyze relevant methods during Android application's runtime.

## Frida Hook for Intercepting HTTP Request Signatures

In the Frida hook - available in this repository as [signature/signature.js](./signature/signature.js) - `C63377r` class is renamed to `SignatureInterceptor`, for the purpose of better readability. This hook overloads three methods of SignatureInterceptor class:

1. SignatureInterceptor.$init:
    * Loads `secret key` into a local variable.
    * Loads `access key` into a local variable. Also a hard coded value, used as a part of HTTP request X-Authorization header.
2. SignatureInterceptor.a:
    * Computes MD5 hash of requestBody.
    * Encodes MD5 hash with Base64.
3. SignatureInterceptor.b:
    * Takes 4 relevant parameters as input.
    * Computes HmacSHA1 hash as HTTP request signature.

For every captured signature a JSON object is generated with some additional metadata:

1. Content type.
2. Content length.
3. Content string.
4. Encoded content string.
5. Timestamp.
6. Nonce.
7. API path.
8. Signature.

If Frida is installed on the host machine via uv package manager, a sample command that spawns an Android application with signature intercepting hook attached could look like this:

```sh
uv run frida -U -f <package-name> -l signature.js
```

Or an updated version that saves both normal output (stdout) and errors (stderr) to a log file:

```sh
uv run frida -U -f <package-name> -l signature.js 2>&1 | tee signature.log
```

Example output from a successful run:

```json
{
  "contentType": "application/json; charset=utf-8",
  "contentLength": "2",
  "contentString": "{}",
  "contentEncoded": "mZFLkyvTelC5g8XnyQrpOw==",
  "timestamp": "9999999999",
  "nonce": "d78ef6b9-d1cb-4610-8219-589833f0c1f8",
  "path": "/api/v2/account/getMFAFeatureStatus",
  "signature": "a7356d83df620ee3fa326151b212883c458e4d33"
}
```

# Python Implementation

Python implementation of HTTP request signature building is available in this repository as [signature.py](./signature.py).
