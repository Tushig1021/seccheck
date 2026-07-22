<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?= isset($pageTitle) ? htmlspecialchars($pageTitle) . " - SecCheck" : "SecCheck" ?></title>
    <link rel="stylesheet" href="/seccheck/assets/style.css">
</head>
<body>
    <div class="termbar">
        <div class="termbar-left">
            <div class="termdots"><span></span><span></span><span></span></div>
            <div class="termbar-title">
                <?= htmlspecialchars($_SESSION["username"] ?? "guest") ?>@<strong>seccheck</strong>:~$
            </div>
        </div>
        <nav class="termbar-nav">
            <?php if (isset($_SESSION["user_id"])): ?>
                <a href="diagnose.php">diagnose</a>
                <a href="history.php">history</a>
                <a href="logout.php">logout</a>
            <?php else: ?>
                <a href="login.php">login</a>
                <a href="register.php">register</a>
            <?php endif; ?>
        </nav>
    </div>
    <div class="page">
        <div class="pane">
