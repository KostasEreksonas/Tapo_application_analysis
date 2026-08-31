'use strict';

let accessKey = "";
let secretKey = "";

const Log = Java.use("android.util.Log");
const Throwable = Java.use("java.lang.Throwable");

function traceStack() {
    return Log.getStackTraceString(Throwable.$new());
}

function logging(state) {
    console.log(JSON.stringify(state, null, 2));
}

function currentThreadId(Thread) {
    return Thread.currentThread().getId().toString();
}

function bytesToString(bytes) {
    if (bytes === null || bytes === undefined) return "<null>";

    let result = "";

    for (let i = 0; i < bytes.length; ++i) {
        // Only convert printable ASCII characters (32-126); otherwise, use a placeholder dot (.)
        let val = bytes[i] & 0xFF;  // Get unsigned byte value

        if (val === 10) {
            result += "\\n";
        } else if (val === 13) {
            result += "\\r";
        } else if (val === 9) {
            result += "\\t";
        } else if (val >= 32 && val <= 126) {
            result += String.fromCharCode(val);
        } else {
            result += '.';
        }
    }

    return result;
}

Java.perform(function () {
    const Buffer = Java.use("okio.Buffer"); // Required for okhttp3.RequestBody.writeTo(okio.BufferedSing sink)
    const Thread = Java.use("java.lang.Thread"); // Using ThreadID to track OkHttp interceptor chain (it is only assumed that all methods run on the same thread)
    const RetrofitInvocation = Java.use("retrofit2.s"); // For parsing a typed tag in HTTP request
    const className = "l7.r"; // Obfuscated signature building class name in com.tplink.iot. Likely to change with an app update.
    const SignatureInterceptor = Java.use(className);
    const requestBodies = new Map();

    try {
        const initSignature = SignatureInterceptor.$init.overload(
            "java.lang.String",
            "java.lang.String"
        );

        initSignature.implementation = function (accessKeyVal, secretKeyVal) {
            initSignature.call(this, accessKeyVal, secretKeyVal);

            accessKey = accessKeyVal;
            secretKey = secretKeyVal;
        };
    } catch (e) {
        console.log("Error during init: " + e.message);
    }

    try {
        const encodeSignature = SignatureInterceptor.a.overload(
            "okhttp3.RequestBody"
        );

        encodeSignature.implementation = function (requestBody) {
            // Overloaded function hashes the requestBody with MD5 and encodes it with Base64
            const result = encodeSignature.call(this, requestBody);
            const requestBodyThreadId = currentThreadId(Thread);

            let buffer = Buffer.$new();
            requestBody.writeTo(buffer);
            const bytes = buffer.readByteArray();

            const requestBodyState = {
                threadId: requestBodyThreadId,
                accessKey: accessKey,
                secretKey: secretKey,
                contentType: requestBody.contentType().toString(),
                contentLength: requestBody.contentLength(),
                contentString: bytesToString(bytes),
                contentEncoded: result
            };

            requestBodies.set(requestBodyThreadId, requestBodyState);

            return result;
        };
    } catch (e) {
        console.log("Error with request body: " + e.message);
    }

    try {
        const buildSignature = SignatureInterceptor.b.overload(
            "java.lang.String",
            "long",
            "java.lang.String",
            "java.lang.String"
        );

        buildSignature.implementation = function (body, timestamp, nonce, path) {
            const result = buildSignature.call(this, body, timestamp, nonce, path);
            const requestBodyThreadId = currentThreadId(Thread);

            let state = requestBodies.get(requestBodyThreadId);

            if (state !== undefined) {
                state.timestamp = timestamp;
                state.nonce = nonce;
                state.path = path;
                state.signature = result;
            }

            return result;
        };
    } catch (e) {
        console.log("Error building signature: " + e.message);
    }

    try {
        const interceptorChain = SignatureInterceptor.intercept.overload(
            "okhttp3.Interceptor$Chain"
        );

        interceptorChain.implementation = function (chain) {
            const Response = interceptorChain.call(this, chain);
            const Request = chain.request();

            const headers = Request.headers();
            const headerArray = [];
            for (let i = 0; i < headers.size(); i++) {
                headerArray.push({
                    name: headers.name(i).toString(),
                    value: headers.value(i).toString()
                });
            }

            const requestMethod = Request.method();
            const requestUrl = Request.url();
            const typedTag = Request.tag.overload("java.lang.Class").call(Request, RetrofitInvocation.class).toString();

            const queryParameters = Request.url().queryParameterNames();
            const queryParametersArray = [];

            for (let i = 0; i < queryParameters.size(); i++) {
                queryParametersArray.push({
                    name: requestUrl.queryParameterName(i).toString(),
                    value: requestUrl.queryParameterValue(i).toString()
                });
            }

            const requestState = {
                method: requestMethod,
                url: requestUrl.toString(),
                urlParameterNames: queryParametersArray,
                headers: headerArray,
                tags: typedTag
            };

            const protocol = Response.protocol().toString();
            const code = Response.code();
            const message = Response.message();

            const responseBody = Response.body();
            const responsePeeked = Response.peekBody(responseBody.contentLength());
            const body = responsePeeked.string();

            const responseState = {
                protocol: protocol,
                code: code,
                message: message,
                body: body
            };

            const requestBodyThreadId = currentThreadId(Thread);
            let state = requestBodies.get(requestBodyThreadId);

            if (state !== undefined) {
                state.request = requestState;
                state.response = responseState;
                //state.stackTrace = traceStack();

                logging(state);
                requestBodies.delete(requestBodyThreadId);
            } else {
                const requestBodyThreadId = currentThreadId(Thread);
                const state = {
                    threadId: requestBodyThreadId,
                    comment: "Initial state not captured",
                    request: requestState,
                    response: responseState
                }

                logging(state);
            }

            return Response;
        };
    } catch (e) {
        console.log("Interceptor chain error: " + e.message);
    }
});
