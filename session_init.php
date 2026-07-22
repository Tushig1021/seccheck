<?php
// centralized session setup - hardens the session cookie before starting the session.
// must be included instead of calling session_start() directly, so every page
// gets the same protections automatically.

session_set_cookie_params([
    "lifetime" => 0,        // cookie expires when the browser closes
    "path" => "/",
    "httponly" => true,     // JavaScript cannot read this cookie - blocks session theft via XSS
    "samesite" => "Lax",    // cookie isn't sent on most cross-site requests - adds CSRF defense
    // "secure" => true,     // uncomment once the site is served over HTTPS
]);

session_start();
