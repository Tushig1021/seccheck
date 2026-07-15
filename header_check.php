<?php

function checkHeaders($url) {
    // make sure the URL has a scheme, otherwise get_headers() fails silently
    if (!preg_match("~^https?://~i", $url)) {
        $url = "https://" . $url;
    }

    $headers = @get_headers($url, 1);

    if ($headers === false) {
        return ["error" => "Could not fetch headers. Is the host reachable?"];
    }

    // get_headers() returns keys inconsistently cased depending on the server,
    // so normalize everything to lowercase for reliable checks
    $normalized = [];
    foreach ($headers as $key => $value) {
        if (is_int($key)) {
            continue; // skip the raw "HTTP/1.1 200 OK" status line entry
        }
        $normalized[strtolower($key)] = $value;
    }

    return scoreHeaders($normalized);
}

function scoreHeaders($headers) {
    $result = [
        "checks" => [],
        "score" => 100,
    ];

    // Each entry: header name => points to deduct if missing
    $securityHeaders = [
        "strict-transport-security" => 20, // forces HTTPS, prevents downgrade attacks
        "content-security-policy"   => 20, // mitigates XSS by restricting script sources
        "x-frame-options"           => 15, // prevents clickjacking via iframes
        "x-content-type-options"    => 10, // stops MIME-sniffing attacks
        "referrer-policy"           => 10, // controls what leaks via the Referer header
    ];

    foreach ($securityHeaders as $headerName => $penalty) {
        if (isset($headers[$headerName])) {
            $result["checks"][$headerName] = [
                "pass" => true,
                "detail" => "Present",
            ];
        } else {
            $result["checks"][$headerName] = [
                "pass" => false,
                "detail" => "Missing",
            ];
            $result["score"] -= $penalty;
        }
    }

    $result["score"] = max(0, min(100, $result["score"]));

    return $result;
}

// --- quick manual test ---
if (php_sapi_name() === "cli" && isset($argv[1])) {
    $result = checkHeaders($argv[1]);
    print_r($result);
}
