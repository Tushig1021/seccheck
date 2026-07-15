<?php
require_once "config.php";

function getDbConnection() {
    static $conn = null; // reuse the same connection if called more than once per request

    if ($conn === null) {
        $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($conn->connect_error) {
            die("Database connection failed: " . $conn->connect_error);
        }
    }

    return $conn;
}
