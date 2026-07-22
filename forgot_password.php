<?php
require_once "session_init.php";
require_once "csrf.php";
require_once "db.php";
require_once "mailer.php";
$conn = getDbConnection();

$message = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    verifyCsrfToken();
    $email = trim($_POST["email"] ?? "");

    if ($email !== "") {
        $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        // only send an email if the account actually exists, but show the
        // same message either way - don't reveal whether an email is registered
        if ($user) {
            $token = bin2hex(random_bytes(32));
            $tokenStmt = $conn->prepare(
                "INSERT INTO password_resets (user_id, token, expires_at)
                 VALUES (?, ?, NOW() + INTERVAL 30 MINUTE)"
            );
            $tokenStmt->bind_param("is", $user["id"], $token);
            $tokenStmt->execute();
            $tokenStmt->close();

            $host = $_SERVER["HTTP_HOST"];
            $resetLink = "http://$host/seccheck/reset_password.php?token=$token";

            sendEmail(
                $email,
                "Reset your SecCheck password",
                "We received a request to reset your SecCheck password.\n\nClick this link to choose a new password:\n$resetLink\n\nThis link expires in 30 minutes. If you didn't request this, you can ignore this email."
            );
        }
    }

    $message = "If that email is registered, a password reset link has been sent.";
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>SecCheck - Forgot Password</title>
</head>
<body>
    <h1>Forgot Password</h1>

    <?php if ($message): ?>
        <p style="color:green;"><?= htmlspecialchars($message) ?></p>
    <?php else: ?>
        <form method="POST" action="forgot_password.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">
            <label for="email">Email:</label><br>
            <input type="email" id="email" name="email" required><br><br>
            <button type="submit">Send Reset Link</button>
        </form>
    <?php endif; ?>

    <p><a href="login.php">Back to login</a></p>
</body>
</html>
