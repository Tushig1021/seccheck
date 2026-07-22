<?php
require_once "session_init.php";
require_once "csrf.php";
require_once "db.php";
$conn = getDbConnection();
$error = "";

$MAX_ATTEMPTS = 5;
$LOCKOUT_SECONDS = 30;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    verifyCsrfToken();
    $username = trim($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";

    if ($username === "" || $password === "") {
        $error = "Username and password are required.";
    } else {
        $stmt = $conn->prepare(
            "SELECT COUNT(*) AS attempts FROM login_attempts
             WHERE username = ? AND attempted_at > (NOW() - INTERVAL ? SECOND)"
        );
        $stmt->bind_param("si", $username, $LOCKOUT_SECONDS);
        $stmt->execute();
        $attemptCount = $stmt->get_result()->fetch_assoc()["attempts"];
        $stmt->close();

        if ($attemptCount >= $MAX_ATTEMPTS) {
            $error = "Too many failed attempts. Please wait $LOCKOUT_SECONDS seconds and try again.";
        } else {
            $stmt = $conn->prepare("SELECT id, password_hash, email_verified FROM users WHERE username = ?");
            $stmt->bind_param("s", $username);
            $stmt->execute();
            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            $stmt->close();

            if ($user && password_verify($password, $user["password_hash"])) {
                if (!$user["email_verified"]) {
                    $error = "Please verify your email before logging in. Check your inbox for the verification link.";
                } else {
                    $clearStmt = $conn->prepare("DELETE FROM login_attempts WHERE username = ?");
                    $clearStmt->bind_param("s", $username);
                    $clearStmt->execute();
                    $clearStmt->close();

                    session_regenerate_id(true);
                    $_SESSION["user_id"] = $user["id"];
                    $_SESSION["username"] = $username;
                    header("Location: diagnose.php");
                    exit;
                }
            } else {
                $logStmt = $conn->prepare("INSERT INTO login_attempts (username) VALUES (?)");
                $logStmt->bind_param("s", $username);
                $logStmt->execute();
                $logStmt->close();

                $error = "Invalid username or password.";
            }
        }
    }
}

$pageTitle = "Login";
require_once "includes/header.php";
?>

<h1>login</h1>

<?php if ($error): ?>
    <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>

<form method="POST" action="login.php">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">
    <label for="username">username</label>
    <input type="text" id="username" name="username"
           value="<?= htmlspecialchars($_POST["username"] ?? "") ?>" required>

    <label for="password">password</label>
    <input type="password" id="password" name="password" required>

    <button type="submit">authenticate</button>
</form>

<p style="margin-top:20px; font-size:13px;">
    <a href="forgot_password.php">forgot password?</a> &nbsp;·&nbsp;
    <a href="register.php">create account</a>
</p>

<?php require_once "includes/footer.php"; ?>
