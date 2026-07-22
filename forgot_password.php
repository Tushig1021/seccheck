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

$pageTitle = "Forgot Password";
require_once "includes/header.php";
?>

<h1>forgot_password</h1>

<?php if ($message): ?>
    <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
<?php else: ?>
    <form method="POST" action="forgot_password.php">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">
        <label for="email">email</label>
        <input type="email" id="email" name="email" required>
        <button type="submit">send_reset_link</button>
    </form>
<?php endif; ?>

<p style="margin-top:20px; font-size:13px;"><a href="login.php">back to login</a></p>

<?php require_once "includes/footer.php"; ?>
