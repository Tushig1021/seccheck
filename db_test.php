<?php
$conn = new mysqli("localhost", "seccheck_user", "20051021b", "seccheck_db");
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
echo "Connected successfully!";
?>
