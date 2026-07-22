<?php
require_once "db.php";
$conn = getDbConnection();

$message = "";
$success = false;

$token = $_GET["token"] ?? "";

if ($token === "") {
    $message = "No verification token provided.";
} else {
    $stmt = $conn->prepare(
        "SELECT user_id, expires_at FROM email_verifications WHERE token = ?"
    );
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $stmt->close();

    if (!$row) {
        $message = "This verification link is invalid.";
    } elseif (strtotime($row["expires_at"]) < time()) {
        $message = "This verification link has expired. Please register again or request a new link.";
    } else {
        $updateStmt = $conn->prepare("UPDATE users SET email_verified = 1 WHERE id = ?");
        $updateStmt->bind_param("i", $row["user_id"]);
        $updateStmt->execute();
        $updateStmt->close();

        $deleteStmt = $conn->prepare("DELETE FROM email_verifications WHERE token = ?");
        $deleteStmt->bind_param("s", $token);
        $deleteStmt->execute();
        $deleteStmt->close();

        $success = true;
        $message = "Your email has been verified! You can now log in.";
    }
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>SecCheck - Email Verification</title>
</head>
<body>
    <h1>Email Verification</h1>
    <p style="color:<?= $success ? "green" : "red" ?>;"><?= htmlspecialchars($message) ?></p>
    <?php if ($success): ?>
        <p><a href="login.php">Go to login</a></p>
    <?php endif; ?>
</body>
</html>
