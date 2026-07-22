<?php
require_once "session_init.php";
require_once "csrf.php";
require_once "db.php";
$conn = getDbConnection();

$error = "";
$success = false;
$token = $_GET["token"] ?? $_POST["token"] ?? "";

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

        $usedStmt = $conn->prepare("UPDATE password_resets SET used = 1 WHERE token = ?");
        $usedStmt->bind_param("s", $token);
        $usedStmt->execute();
        $usedStmt->close();

        $success = true;
    }
}

$pageTitle = "Reset Password";
require_once "includes/header.php";
?>

<h1>reset_password</h1>

<?php if ($success): ?>
    <div class="alert alert-success">Your password has been reset. You can now log in.</div>
    <p><a href="login.php">go to login</a></p>
<?php elseif ($error && !$tokenValid): ?>
    <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
<?php else: ?>
    <?php if ($error): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <form method="POST" action="reset_password.php">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">
        <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">
        <label for="password">new_password</label>
        <input type="password" id="password" name="password" required>
        <label for="confirm_password">confirm_new_password</label>
        <input type="password" id="confirm_password" name="confirm_password" required>
        <button type="submit">reset_password</button>
    </form>
<?php endif; ?>

<?php require_once "includes/footer.php"; ?>
