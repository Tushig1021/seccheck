<?php
// call this once per page, after session_start()
function getCsrfToken() {
    if (empty($_SESSION["csrf_token"])) {
        $_SESSION["csrf_token"] = bin2hex(random_bytes(32));
    }
    return $_SESSION["csrf_token"];
}

// call this at the top of any POST handler
function verifyCsrfToken() {
    $submitted = $_POST["csrf_token"] ?? "";
    $expected = $_SESSION["csrf_token"] ?? "";

    if ($expected === "" || !hash_equals($expected, $submitted)) {
        http_response_code(403);
        die("Invalid or missing security token. Please go back and try again.");
    }
}
