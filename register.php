<?php
require_once "session_init.php";
require_once "csrf.php";
require_once "db.php";
require_once "mailer.php";
$conn = getDbConnection();
$error = "";
$success = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    verifyCsrfToken();
    $username = trim($_POST["username"] ?? "");
    $email = trim($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";

    if ($username === "" || $email === "" || $password === "") {
        $error = "All fields are required.";
    } elseif (strlen($username) < 3) {
        $error = "Username must be at least 3 characters.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Please enter a valid email address.";
    } elseif (strlen($password) < 8) {
        $error = "Password must be at least 8 characters.";
    } elseif ($password !== $confirmPassword) {
        $error = "Passwords do not match.";
    } else {
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->bind_param("ss", $username, $email);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $error = "That username or email is already registered.";
        } else {
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);

            $insertStmt = $conn->prepare(
                "INSERT INTO users (username, email, password_hash, email_verified) VALUES (?, ?, ?, 0)"
            );
            $insertStmt->bind_param("sss", $username, $email, $passwordHash);

            if ($insertStmt->execute()) {
                $newUserId = $insertStmt->insert_id;

                $token = bin2hex(random_bytes(32));
                $tokenStmt = $conn->prepare(
                    "INSERT INTO email_verifications (user_id, token, expires_at)
                     VALUES (?, ?, NOW() + INTERVAL 24 HOUR)"
                );
                $tokenStmt->bind_param("is", $newUserId, $token);
                $tokenStmt->execute();
                $tokenStmt->close();

                $host = $_SERVER["HTTP_HOST"];
                $verifyLink = "http://$host/seccheck/verify_email.php?token=$token";

                $emailSent = sendEmail(
                    $email,
                    "Verify your SecCheck account",
                    "Welcome to SecCheck!\n\nPlease verify your email by clicking this link:\n$verifyLink\n\nThis link expires in 24 hours."
                );

                if ($emailSent) {
                    $success = true;
                } else {
                    $error = "Account created, but the verification email could not be sent. Please contact support.";
                }
            } else {
                $error = "Something went wrong. Please try again.";
            }
            $insertStmt->close();
        }
        $stmt->close();
    }
}

$pageTitle = "Register";
require_once "includes/header.php";
?>

<h1>register</h1>

<?php if ($success): ?>
    <div class="alert alert-success">Account created. Check your email to verify before logging in.</div>
    <p><a href="login.php">go to login</a></p>
<?php else: ?>
    <?php if ($error): ?>
        <div class="alert alert-error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <form method="POST" action="register.php">
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">

        <label for="username">username</label>
        <input type="text" id="username" name="username"
               value="<?= htmlspecialchars($_POST["username"] ?? "") ?>" required>

        <label for="email">email</label>
        <input type="email" id="email" name="email"
               value="<?= htmlspecialchars($_POST["email"] ?? "") ?>" required>

        <label for="password">password</label>
        <input type="password" id="password" name="password" required>

        <label for="confirm_password">confirm_password</label>
        <input type="password" id="confirm_password" name="confirm_password" required>

        <button type="submit">create_account</button>
    </form>

    <p style="margin-top:20px; font-size:13px;">
        already have an account? <a href="login.php">login</a>
    </p>
<?php endif; ?>

<?php require_once "includes/footer.php"; ?>
