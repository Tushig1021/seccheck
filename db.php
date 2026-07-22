<?php
require_once "config.php";

function getDbConnection() {
    static $conn = null;

    if ($conn === null) {
        try {
            $conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        } catch (mysqli_sql_exception $e) {
            error_log("Database connection failed: " . $e->getMessage());
            die("A system error occurred. Please try again later.");
        }
    }

    return $conn;
}
