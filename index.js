//
// Proxy Backblaze S3 compatible API requests, sending notifications to a webhook
//
// Adapted from https://github.com/obezuk/worker-signed-s3-template
//
import { AwsClient } from 'aws4fetch'

const UNSIGNABLE_HEADERS = [
    // These headers appear in the request, but are never passed upstream
    'x-forwarded-proto',
    'x-real-ip',
    // We can't include accept-encoding in the signature because Cloudflare
    // sets the incoming accept-encoding header to "gzip, br", then modifies
    // the outgoing request to set accept-encoding to "gzip".
    // Not cool, Cloudflare!
    'accept-encoding',
    // Conditional headers are not consistently passed upstream
    'if-match',
    'if-modified-since',
    'if-none-match',
    'if-range',
    'if-unmodified-since',
];

// URL needs colon suffix on protocol, and port as a string
const HTTPS_PROTOCOL = "https:";
const HTTPS_PORT = "443";

// How many times to retry a range request where the response is missing content-range
const RANGE_RETRY_ATTEMPTS = 3;

function uriEncode(value) {
    return encodeURIComponent(value).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

function canonicalUri(pathname) {
    if (!pathname || pathname === "/") return "/";
    return pathname.split("/").map((segment) => {
        try {
            return uriEncode(decodeURIComponent(segment));
        } catch {
            return uriEncode(segment);
        }
    }).join("/");
}

function canonicalQuery(url) {
    const pairs = [];
    for (const [key, value] of url.searchParams.entries()) {
        if (key.toLowerCase() === "x-amz-signature") continue;
        pairs.push([uriEncode(key), uriEncode(value)]);
    }
    pairs.sort((left, right) => (left[0] === right[0] ? (left[1] < right[1] ? -1 : left[1] > right[1] ? 1 : 0) : left[0] < right[0] ? -1 : 1));
    return pairs.map(([key, value]) => `${key}=${value}`).join("&");
}

async function hmac(keyBytes, data) {
    const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new Uint8Array(await crypto.subtle.sign("HMAC", key, typeof data === "string" ? new TextEncoder().encode(data) : data));
}

function hex(bytes) {
    return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function safeEqual(left, right) {
    if (left.length !== right.length) return false;
    let mismatch = 0;
    for (let index = 0; index < left.length; index += 1) mismatch |= left.charCodeAt(index) ^ right.charCodeAt(index);
    return mismatch === 0;
}

// Alist signs the custom host. B2 would reject that Host, so check it here, then the caller re-signs upstream.
async function verifyIncomingPresign(url, request, env) {
    const algorithm = url.searchParams.get("X-Amz-Algorithm");
    const credential = url.searchParams.get("X-Amz-Credential") || "";
    const amzDate = url.searchParams.get("X-Amz-Date") || "";
    const signature = (url.searchParams.get("X-Amz-Signature") || "").toLowerCase();
    const signedHeaders = (url.searchParams.get("X-Amz-SignedHeaders") || "").toLowerCase();
    const expires = Number(url.searchParams.get("X-Amz-Expires"));
    const parts = credential.split("/");
    if (algorithm !== "AWS4-HMAC-SHA256" || parts.length !== 5 || !signature || !signedHeaders) return "credential";
    const [accessKey, dateStamp, region, service, terminator] = parts;
    // Dashboard/wrangler values often include a trailing newline. Alist's region (usually "alist") is not the B2 region.
    const keyId = String(env.B2_APPLICATION_KEY_ID || "").trim().replace(/^["']|["']$/g, "");
    if (accessKey !== keyId || service !== "s3" || terminator !== "aws4_request") return "credential";
    if (!amzDate.startsWith(dateStamp) || amzDate.length < 16) return "date";
    if (!Number.isFinite(expires) || expires <= 0) return "expires";
    const issued = Date.UTC(
        Number(amzDate.slice(0, 4)),
        Number(amzDate.slice(4, 6)) - 1,
        Number(amzDate.slice(6, 8)),
        Number(amzDate.slice(9, 11)),
        Number(amzDate.slice(11, 13)),
        Number(amzDate.slice(13, 15)),
    );
    const now = Date.now();
    if (Number.isNaN(issued) || now > issued + expires * 1000 + 60000 || now + 60000 < issued) return "expired";

    const names = signedHeaders.split(";");
    let canonicalHeaders = "";
    for (const name of names) {
        let value = name === "host" ? request.headers.get("host") || url.host : request.headers.get(name) || "";
        value = value.trim().replace(/\s+/g, " ");
        if (!value) return "headers";
        canonicalHeaders += `${name}:${value}\n`;
    }
    const payload = names.includes("x-amz-content-sha256")
        ? request.headers.get("x-amz-content-sha256") || url.searchParams.get("X-Amz-Content-Sha256") || "UNSIGNED-PAYLOAD"
        : "UNSIGNED-PAYLOAD";
    const canonical = [
        request.method,
        canonicalUri(url.pathname),
        canonicalQuery(url),
        canonicalHeaders,
        signedHeaders,
        payload,
    ].join("\n");
    const canonicalHash = hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical))));
    const scope = `${dateStamp}/${region}/${service}/${terminator}`;
    const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${scope}\n${canonicalHash}`;
    const secret = new TextEncoder().encode(`AWS4${String(env.B2_APPLICATION_KEY || "").trim().replace(/^["']|["']$/g, "")}`);
    const signingKey = await hmac(await hmac(await hmac(await hmac(secret, dateStamp), region), service), "aws4_request");
    const expected = hex(await hmac(signingKey, stringToSign));
    return safeEqual(expected, signature) ? "" : "signature";
}


// Filter out cf-* and any other headers we don't want to include in the signature
function filterHeaders(headers, env) {
    // Suppress irrelevant IntelliJ warning
    // noinspection JSCheckFunctionSignatures
    return new Headers(Array.from(headers.entries())
        .filter(pair => !(
            UNSIGNABLE_HEADERS.includes(pair[0])
            || pair[0].startsWith('cf-')
            || ('ALLOWED_HEADERS' in env && !env['ALLOWED_HEADERS'].includes(pair[0]))
        ))
    );
}

function createHeadResponse(response) {
    return new Response(null, {
        headers: response.headers,
        status: response.status,
        statusText: response.statusText
    });
}

function isListBucketRequest(env, path) {
    const pathSegments = path.split('/');

    return (env['BUCKET_NAME'] === "$path" && pathSegments.length < 2) // https://endpoint/bucket-name/
        || (env['BUCKET_NAME'] !== "$path" && path.length === 0); // https://bucket-name.endpoint/ or https://endpoint/
}

// Supress IntelliJ's "unused default export" warning
// noinspection JSUnusedGlobalSymbols
export default {
    async fetch(request, env) {
        // Only allow GET and HEAD methods
        if (!['GET', 'HEAD'].includes(request.method)){
            return new Response(null, {
                status: 405,
                statusText: "Method Not Allowed"
            });
        }

        const url = new URL(request.url);
        if (!url.searchParams.has("X-Amz-Signature")) {
            return new Response("unauthorized", { status: 401, statusText: "Unauthorized" });
        }
        const presignError = await verifyIncomingPresign(url, request, env);
        if (presignError) {
            return new Response(presignError, { status: 403, statusText: "Forbidden" });
        }
        for (const key of [...url.searchParams.keys()]) {
            if (key.toLowerCase().startsWith("x-amz-")) url.searchParams.delete(key);
        }

        // Incoming protocol and port is taken from the worker's environment.
        // Local dev mode uses plain http on 8787, and it's possible to deploy
        // a worker on plain http. B2 only supports https on 443
        url.protocol = HTTPS_PROTOCOL;
        url.port = HTTPS_PORT;

        // Remove leading slashes from path
        let path = url.pathname.replace(/^\//, '');
        // Remove trailing slashes
        path = path.replace(/\/$/, '');

        // Reject list bucket requests unless configuration allows it
        if (isListBucketRequest(env, path) && String(env['ALLOW_LIST_BUCKET']) !== "true") {
            return new Response(null, {
                status: 404,
                statusText: "Not Found"
            });
        }

        // Set RCLONE_DOWNLOAD to "true" to use rclone with --b2-download-url
        // See https://rclone.org/b2/#b2-download-url
        const rcloneDownload = String(env["RCLONE_DOWNLOAD"]) === 'true';

        // Set upstream target hostname.
        switch (env['BUCKET_NAME']) {
            case "$path":
                // Bucket name is initial segment of URL path
                url.hostname = env['B2_ENDPOINT'];
                break;
            case "$host":
                // Bucket name is initial subdomain of the incoming hostname
                url.hostname = url.hostname.split('.')[0] + '.' + env['B2_ENDPOINT'];
                break;
            default:
                // Bucket name is specified in the BUCKET_NAME variable
                url.hostname = env['BUCKET_NAME'] + "." + env['B2_ENDPOINT'];
                break;
        }

        // Certain headers, such as x-real-ip, appear in the incoming request but
        // are removed from the outgoing request. If they are in the outgoing
        // signed headers, B2 can't validate the signature.
        const headers = filterHeaders(request.headers, env);
        headers.delete("authorization");
        for (const key of [...headers.keys()]) {
            if (key.toLowerCase().startsWith("x-amz-")) headers.delete(key);
        }

        // Create an S3 API client that can sign the outgoing request
        const client = new AwsClient({
            "accessKeyId": env['B2_APPLICATION_KEY_ID'],
            "secretAccessKey": env['B2_APPLICATION_KEY'],
            "service": "s3",
        });

        // Save the request method, so we can process responses for HEAD requests appropriately
        const requestMethod = request.method;

        if (rcloneDownload) {
            if (env['BUCKET_NAME'] === "$path") {
                // Remove leading file/ prefix from the path
                url.pathname = path.replace(/^file\//, "");
            } else {
                // Remove leading file/{bucket_name}/ prefix from the path 
                url.pathname = path.replace(/^file\/[^/]+\//, "");
            }            
        }

        // Sign the outgoing request
        //
        // For HEAD requests Cloudflare appears to change the method on the outgoing request to GET (#18), which
        // breaks the signature, resulting in a 403. So, change all HEADs to GETs. This is not too inefficient,
        // since we won't read the body of the response if the original request was a HEAD.
        const signedRequest = await client.sign(url.toString(), {
            method: 'GET',
            headers: headers
        });

        // For large files, Cloudflare will return the entire file, rather than the requested range
        // So, if there is a range header in the request, check that the response contains the
        // content-range header. If not, abort the request and try again.
        // See https://community.cloudflare.com/t/cloudflare-worker-fetch-ignores-byte-request-range-on-initial-request/395047/4
        if (signedRequest.headers.has("range")) {
            let attempts = RANGE_RETRY_ATTEMPTS;
            let response;
            do {
                let controller = new AbortController();
                response = await fetch(signedRequest.url, {
                    method: signedRequest.method,
                    headers: signedRequest.headers,
                    signal: controller.signal,
                });
                if (response.headers.has("content-range")) {
                    // Only log if it didn't work first time
                    if (attempts < RANGE_RETRY_ATTEMPTS) {
                        console.log(`Retry for ${signedRequest.url} succeeded - response has content-range header`);
                    }
                    // Break out of loop and return the response
                    break;
                } else if (response.ok) {
                    attempts -= 1;
                    console.error(`Range header in request for ${signedRequest.url} but no content-range header in response. Will retry ${attempts} more times`);
                    // Do not abort on the last attempt, as we want to return the response
                    if (attempts > 0) {
                        controller.abort();
                    }
                } else {
                    // Response is not ok, so don't retry
                    break;
                }
            } while (attempts > 0);

            if (attempts <= 0) {
                console.error(`Tried range request for ${signedRequest.url} ${RANGE_RETRY_ATTEMPTS} times, but no content-range in response.`);
            }

            if (requestMethod === 'HEAD') {
                // Original request was HEAD, so return a new Response without a body
                return createHeadResponse(response);
            }

            // Return whatever response we have rather than an error response
            // This response cannot be aborted, otherwise it will raise an exception
            return response;
        }

        // Send the signed request to B2
        const fetchPromise = fetch(signedRequest);

        if (requestMethod === 'HEAD') {
            const response = await fetchPromise;
            // Original request was HEAD, so return a new Response without a body
            return createHeadResponse(response);
        }

        // Return the upstream response unchanged
        return fetchPromise;
    },
};



