<?php
session_start();
require_once "ssl_check.php";
require_once "header_check.php";
require_once "db.php";
$conn = getDbConnection();
$currentUserId = $_SESSION["user_id"];

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

$result = null;
$submittedUrl = "";

if ($_SERVER["REQUEST_METHOD"] === "POST" && !empty($_POST["url"])) {
    $submittedUrl = trim($_POST["url"]);

    // basic validation - must look like a real host, not blank/garbage input
    $host = parse_url(
        preg_match("~^https?://~i", $submittedUrl) ? $submittedUrl : "https://" . $submittedUrl,
        PHP_URL_HOST
    );

    if (!$host) {
        $result = ["error" => "That doesn't look like a valid URL."];
    } else {
        $sslResult = checkSSL($host);
        $headerResult = checkHeaders($host);

        $sslScore = $sslResult["score"] ?? 0;
        $headerScore = $headerResult["score"] ?? 0;
        $totalScore = round(($sslScore + $headerScore) / 2);

        $result = [
            "host" => $host,
            "ssl" => $sslResult,
            "headers" => $headerResult,
            "total_score" => $totalScore,
        ];

        // save this diagnosis to the database
        $sslDetailsJson = json_encode($sslResult["checks"] ?? []);
        $headerDetailsJson = json_encode($headerResult["checks"] ?? []);

        $stmt = $conn->prepare(
            "INSERT INTO diagnoses (user_id, url, ssl_score, header_score, total_score, ssl_details, header_details)
             VALUES (?, ?, ?, ?, ?, ?, ?)"
        );
        $stmt->bind_param(
            "isiiiss",
            $currentUserId,
            $host,
            $sslScore,
            $headerScore,
            $totalScore,
            $sslDetailsJson,
            $headerDetailsJson
        );

        if (!$stmt->execute()) {
            $result["save_error"] = "Could not save to database: " . $stmt->error;
        }
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>SecCheck - Website Security Diagnosis</title>
</head>
<body>
    <h1>SecCheck</h1>

    <form method="POST" action="diagnose.php">
        <label for="url">Website URL:</label>
        <input type="text" id="url" name="url" placeholder="example.com"
               value="<?= htmlspecialchars($submittedUrl) ?>" required>
        <button type="submit">Diagnose</button>
    </form>

    <?php if ($result): ?>
        <?php if (isset($result["error"])): ?>
            <p style="color:red;"><?= htmlspecialchars($result["error"]) ?></p>
        <?php else: ?>
            <h2>Results for <?= htmlspecialchars($result["host"]) ?></h2>
            <h3>Total Score: <?= htmlspecialchars($result["total_score"]) ?> / 100</h3>

            <?php if (isset($result["save_error"])): ?>
                <p style="color:red;"><?= htmlspecialchars($result["save_error"]) ?></p>
            <?php else: ?>
                <p style="color:green;">Saved to history.</p>
            <?php endif; ?>

            <h4>SSL/TLS (<?= htmlspecialchars($result["ssl"]["score"] ?? "N/A") ?> / 100)</h4>
            <ul>
                <?php foreach (($result["ssl"]["checks"] ?? []) as $name => $check): ?>
                    <li>
                        <strong><?= htmlspecialchars($name) ?>:</strong>
                        <?= $check["pass"] ? "PASS" : "FAIL" ?>
                        - <?= htmlspecialchars($check["detail"]) ?>
                    </li>
                <?php endforeach; ?>
            </ul>

            <h4>HTTP Headers (<?= htmlspecialchars($result["headers"]["score"] ?? "N/A") ?> / 100)</h4>
            <ul>
                <?php foreach (($result["headers"]["checks"] ?? []) as $name => $check): ?>
                    <li>
                        <strong><?= htmlspecialchars($name) ?>:</strong>
                        <?= $check["pass"] ? "PASS" : "FAIL" ?>
                        - <?= htmlspecialchars($check["detail"]) ?>
                    </li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    <?php endif; ?>
</body>
</html>
