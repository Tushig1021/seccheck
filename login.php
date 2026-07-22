<?php
session_start();
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
        // count recent failed attempts for this username
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
        		// successful login - clear any past failed attempts for this username
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

                // log this failed attempt
                $logStmt = $conn->prepare("INSERT INTO login_attempts (username) VALUES (?)");
                $logStmt->bind_param("s", $username);
                $logStmt->execute();
                $logStmt->close();

                $error = "Invalid username or password.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>SecCheck - Login</title>
</head>
<body>
    <h1>Log In</h1>

    <?php if ($error): ?>
        <p style="color:red;"><?= htmlspecialchars($error) ?></p>
    <?php endif; ?>

    <form method="POST" action="login.php">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"
               value="<?= htmlspecialchars($_POST["username"] ?? "") ?>" required><br><br>

        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" required><br><br>

        <button type="submit">Log In</button>
    </form>
    <p><a href="forgot_password.php">Forgot password?</a></p>
    <p>Don't have an account? <a href="register.php">Register</a></p>
</body>
</html>
