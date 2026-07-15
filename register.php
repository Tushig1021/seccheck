<?php
require_once "config.php";

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

$error = "";
$success = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirmPassword = $_POST["confirm_password"] ?? "";

    if ($username === "" || $password === "") {
        $error = "Username and password are required.";
    } elseif (strlen($username) < 3) {
        $error = "Username must be at least 3 characters.";
    } elseif (strlen($password) < 8) {
        $error = "Password must be at least 8 characters.";
    } elseif ($password !== $confirmPassword) {
        $error = "Passwords do not match.";
    } else {
        // check if username is already taken
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $error = "That username is already taken.";
        } else {
            // hash the password - never store the plain text version
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);

            $insertStmt = $conn->prepare(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)"
            );
            $insertStmt->bind_param("ss", $username, $passwordHash);

            if ($insertStmt->execute()) {
                $success = true;
            } else {
                $error = "Something went wrong. Please try again.";
            }
            $insertStmt->close();
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>SecCheck - Register</title>
</head>
<body>
    <h1>Create an Account</h1>

    <?php if ($success): ?>
        <p style="color:green;">Account created! <a href="login.php">Log in here</a>.</p>
    <?php else: ?>
        <?php if ($error): ?>
            <p style="color:red;"><?= htmlspecialchars($error) ?></p>
        <?php endif; ?>

        <form method="POST" action="register.php">
            <label for="username">Username:</label><br>
            <input type="text" id="username" name="username"
                   value="<?= htmlspecialchars($_POST["username"] ?? "") ?>" required><br><br>

            <label for="password">Password:</label><br>
            <input type="password" id="password" name="password" required><br><br>

            <label for="confirm_password">Confirm Password:</label><br>
            <input type="password" id="confirm_password" name="confirm_password" required><br><br>

            <button type="submit">Register</button>
        </form>

        <p>Already have an account? <a href="login.php">Log in</a></p>
    <?php endif; ?>
</body>
</html>
