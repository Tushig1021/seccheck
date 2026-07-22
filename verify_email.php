<?php
require_once "session_init.php";
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

$pageTitle = "Verify Email";
require_once "includes/header.php";
?>

<h1>verify_email</h1>

<div class="alert <?= $success ? "alert-success" : "alert-error" ?>">
    <?= htmlspecialchars($message) ?>
</div>

<?php if ($success): ?>
    <p><a href="login.php">go to login</a></p>
<?php endif; ?>

<?php require_once "includes/footer.php"; ?>
