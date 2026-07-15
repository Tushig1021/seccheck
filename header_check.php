<?php
function checkHeaders($url) {
    if (!preg_match("~^https?://~i", $url)) {
        $url = "https://" . $url;
    }

    // set a timeout so a slow/unresponsive site doesn't hang the page
    $context = stream_context_create([
        "http" => ["timeout" => 10],
        "ssl" => ["timeout" => 10],
    ]);

    $headers = @get_headers($url, 1, $context);

    if ($headers === false) {
        return [
            "error" => "Could not fetch headers for $url. Host may be unreachable.",
            "score" => 0,
            "checks" => [],
        ];
    }

    $normalized = [];
    foreach ($headers as $key => $value) {
        if (is_int($key)) {
            continue;
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
