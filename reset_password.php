<?php
require_once "session_init.php";
require_once "csrf.php";
require_once "db.php";
$conn = getDbConnection();

$error = "";
$success = false;
$token = $_GET["token"] ?? $_POST["token"] ?? "";

// look up the token and validate it before showing the form
$tokenRow = null;
if ($token !== "") {
    $stmt = $conn->prepare(
        "SELECT user_id, expires_at, used FROM password_resets WHERE token = ?"
    );
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();
    $tokenRow = $result->fetch_assoc();
    $stmt->close();
}

$tokenValid = $tokenRow
    && !$tokenRow["used"]
    && strtotime($tokenRow["expires_at"]) > time();

if (!$tokenRow) {
    $error = "This reset link is invalid.";
} elseif ($tokenRow["used"]) {
    $error = "This reset link has already been used.";
} elseif (strtotime($tokenRow["expires_at"]) < time()) {
    $error = "This reset link has expired. Please request a new one.";
} elseif ($_SERVER["REQUEST_METHOD"] === "POST") {
    verifyCsrfToken();
    $password = $_POST["password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";

    if (strlen($password) < 8) {
        $error = "Password must be at least 8 characters.";
    } elseif ($password !== $confirmPassword) {
        $error = "Passwords do not match.";
    } else {
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        $updateStmt = $conn->prepare("UPDATE users SET password_hash = ? WHERE id = ?");
        $updateStmt->bind_param("si", $passwordHash, $tokenRow["user_id"]);
        $updateStmt->execute();
        $updateStmt->close();

        // mark the token used so it can't be replayed
        $usedStmt = $conn->prepare("UPDATE password_resets SET used = 1 WHERE token = ?");
        $usedStmt->bind_param("s", $token);
        $usedStmt->execute();
        $usedStmt->close();

        $success = true;
    }
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>SecCheck - Reset Password</title>
</head>
<body>
    <h1>Reset Password</h1>

    <?php if ($success): ?>
        <p style="color:green;">Your password has been reset. You can now log in.</p>
        <p><a href="login.php">Go to login</a></p>
    <?php elseif ($error && !$tokenValid): ?>
        <p style="color:red;"><?= htmlspecialchars($error) ?></p>
    <?php else: ?>
        <?php if ($error): ?>
            <p style="color:red;"><?= htmlspecialchars($error) ?></p>
        <?php endif; ?>
        <form method="POST" action="reset_password.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">
            <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
            <label for="password">New Password:</label><br>
            <input type="password" id="password" name="password" required><br><br>
            <label for="confirm_password">Confirm New Password:</label><br>
            <input type="password" id="confirm_password" name="confirm_password" required><br><br>
            <button type="submit">Reset Password</button>
        </form>
    <?php endif; ?>
</body>
</html>
