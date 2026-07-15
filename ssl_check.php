<?php

function checkSSL($url) {
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host) {
        $host = $url; // handles being passed a bare domain like "google.com"
    }

    $safeHost = escapeshellarg($host);
    // timeout kills the whole command after 15s, --connect-timeout caps the connection attempt itself
    $output = shell_exec("timeout 15 sslscan --no-colour --connect-timeout=10 $safeHost 2>&1");

    if (!$output || trim($output) === "") {
        return [
            "error" => "Could not reach $host or sslscan produced no output.",
            "score" => 0,
            "checks" => [],
        ];
    }

    if (stripos($output, "connection refused") !== false ||
        stripos($output, "could not resolve") !== false ||
        stripos($output, "connection timed out") !== false) {
        return [
            "error" => "Could not connect to $host: host may be unreachable or invalid.",
            "score" => 0,
            "checks" => [],
        ];
    }

    return parseSSLScanOutput($output);
}
function parseSSLScanOutput($output) {
    $result = [
        "raw" => $output,
        "checks" => [],
        "score" => 100,
    ];

    // --- Check 1: Old TLS protocols enabled (TLS 1.0 / 1.1) ---
    $oldProtocolsEnabled = [];
    foreach (["TLSv1.0", "TLSv1.1"] as $protocol) {
        if (preg_match("/" . preg_quote($protocol, "/") . "\s+enabled/i", $output)) {
            $oldProtocolsEnabled[] = $protocol;
        }
    }

    if (count($oldProtocolsEnabled) > 0) {
        $result["checks"]["old_tls_versions"] = [
            "pass" => false,
            "detail" => "Deprecated protocol(s) enabled: " . implode(", ", $oldProtocolsEnabled),
        ];
        $result["score"] -= 20 * count($oldProtocolsEnabled);
    } else {
        $result["checks"]["old_tls_versions"] = [
            "pass" => true,
            "detail" => "TLS 1.0 and 1.1 are disabled",
        ];
    }

    // --- Check 2: Weak ciphers present (3DES, RC4) ---
    $weakCiphersFound = [];
    foreach (["3DES", "RC4"] as $weakCipher) {
        if (stripos($output, $weakCipher) !== false) {
            $weakCiphersFound[] = $weakCipher;
        }
    }

    if (count($weakCiphersFound) > 0) {
        $result["checks"]["weak_ciphers"] = [
            "pass" => false,
            "detail" => "Weak cipher(s) offered: " . implode(", ", $weakCiphersFound),
        ];
        $result["score"] -= 15 * count($weakCiphersFound);
    } else {
        $result["checks"]["weak_ciphers"] = [
            "pass" => true,
            "detail" => "No weak ciphers (3DES/RC4) detected",
        ];
    }

    // --- Check 3: Certificate validity + expiry ---
    if (preg_match("/Not valid after:\s*(.+)/", $output, $matches)) {
        $expiryString = trim($matches[1]);
        $expiryTimestamp = strtotime($expiryString);

        if ($expiryTimestamp === false) {
            $result["checks"]["certificate"] = [
                "pass" => false,
                "detail" => "Could not parse certificate expiry date",
            ];
            $result["score"] -= 10;
        } else {
            $now = time();
            $daysRemaining = floor(($expiryTimestamp - $now) / 86400);

            if ($expiryTimestamp < $now) {
                $result["checks"]["certificate"] = [
                    "pass" => false,
                    "detail" => "Certificate expired on $expiryString",
                ];
                $result["score"] -= 40;
            } elseif ($daysRemaining < 14) {
                $result["checks"]["certificate"] = [
                    "pass" => false,
                    "detail" => "Certificate expires soon ($daysRemaining days left, on $expiryString)",
                ];
                $result["score"] -= 15;
            } else {
                $result["checks"]["certificate"] = [
                    "pass" => true,
                    "detail" => "Certificate valid until $expiryString ($daysRemaining days remaining)",
                ];
            }
        }
    } else {
        $result["checks"]["certificate"] = [
            "pass" => false,
            "detail" => "Could not find certificate expiry in scan output",
        ];
        $result["score"] -= 10;
    }

    $result["score"] = max(0, min(100, $result["score"]));

    return $result;
}

// --- quick manual test ---
if (php_sapi_name() === "cli" && isset($argv[1])) {
    $result = checkSSL($argv[1]);
    unset($result["raw"]);
    print_r($result);
}
