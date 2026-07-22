<?php
session_start();
require_once "csrf.php";
require_once "ssl_check.php";
require_once "header_check.php";
require_once "db.php";

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

$currentUserId = $_SESSION["user_id"];
$conn = getDbConnection();

$result = null;
$submittedUrl = "";

if ($_SERVER["REQUEST_METHOD"] === "POST" && !empty($_POST["url"])) {
    verifyCsrfToken();
    $submittedUrl = trim($_POST["url"]);

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

        $bothFailed = isset($sslResult["error"]) && isset($headerResult["error"]);

        if ($bothFailed) {
            $result["save_error"] = "Host unreachable — not saved to history.";
        } else {
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
        <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">
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
            <?php if (isset($result["ssl"]["error"])): ?>
                <p style="color:red;"><?= htmlspecialchars($result["ssl"]["error"]) ?></p>
            <?php endif; ?>
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
            <?php if (isset($result["headers"]["error"])): ?>
                <p style="color:red;"><?= htmlspecialchars($result["headers"]["error"]) ?></p>
            <?php endif; ?>
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
