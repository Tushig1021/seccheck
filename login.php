<?php
session_start();
require_once "config.php";

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

$error = "";

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $username = trim($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";

    if ($username === "" || $password === "") {
        $error = "Username and password are required.";
    } else {
        $stmt = $conn->prepare("SELECT id, password_hash FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();
        $stmt->close();

        // password_verify compares the typed password against the stored hash
        // it never needs to "decrypt" the hash - hashing is one-way by design
        if ($user && password_verify($password, $user["password_hash"])) {
            $_SESSION["user_id"] = $user["id"];
            $_SESSION["username"] = $username;
            header("Location: diagnose.php");
            exit;
        } else {
            // deliberately vague - don't reveal whether it was the username
            // or password that was wrong, that helps attackers guess accounts
            $error = "Invalid username or password.";
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
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username"
               value="<?= htmlspecialchars($_POST["username"] ?? "") ?>" required><br><br>

        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" required><br><br>

        <button type="submit">Log In</button>
    </form>

    <p>Don't have an account? <a href="register.php">Register</a></p>
</body>
</html>
