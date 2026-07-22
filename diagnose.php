<?php
require_once "session_init.php";
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

// pick a score badge color class based on the total
function scoreClass($score) {
    if ($score >= 80) return "good";
    if ($score >= 50) return "mid";
    return "bad";
}

$pageTitle = "Diagnose";
require_once "includes/header.php";
?>

<h1>diagnose</h1>

<form method="POST" action="diagnose.php">
    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars(getCsrfToken()) ?>">
    <label for="url">target_url</label>
    <input type="text" id="url" name="url" placeholder="example.com"
           value="<?= htmlspecialchars($submittedUrl) ?>" required>
    <button type="submit">run_scan</button>
</form>

<?php if ($result): ?>
    <?php if (isset($result["error"])): ?>
        <div class="alert alert-error"><?= htmlspecialchars($result["error"]) ?></div>
    <?php else: ?>
        <h2 style="margin-top:32px;"><?= htmlspecialchars($result["host"]) ?></h2>

        <div class="score-badge <?= scoreClass($result["total_score"]) ?> cursor">
            <?= htmlspecialchars($result["total_score"]) ?>/100
        </div>

        <?php if (isset($result["save_error"])): ?>
            <div class="alert alert-error" style="margin-top:16px;"><?= htmlspecialchars($result["save_error"]) ?></div>
        <?php else: ?>
            <div class="alert alert-success" style="margin-top:16px;">saved to history</div>
        <?php endif; ?>

        <h3 style="margin-top:28px;">ssl/tls — <?= htmlspecialchars($result["ssl"]["score"] ?? "n/a") ?>/100</h3>
        <?php if (isset($result["ssl"]["error"])): ?>
            <div class="alert alert-error"><?= htmlspecialchars($result["ssl"]["error"]) ?></div>
        <?php endif; ?>
        <?php foreach (($result["ssl"]["checks"] ?? []) as $name => $check): ?>
            <div class="report-line">
                <span class="tag <?= $check["pass"] ? "tag-pass" : "tag-fail" ?>">
                    [<?= $check["pass"] ? "PASS" : "FAIL" ?>]
                </span>
                <span><strong><?= htmlspecialchars($name) ?>:</strong> <?= htmlspecialchars($check["detail"]) ?></span>
            </div>
        <?php endforeach; ?>

        <h3 style="margin-top:28px;">http headers — <?= htmlspecialchars($result["headers"]["score"] ?? "n/a") ?>/100</h3>
        <?php if (isset($result["headers"]["error"])): ?>
            <div class="alert alert-error"><?= htmlspecialchars($result["headers"]["error"]) ?></div>
        <?php endif; ?>
        <?php foreach (($result["headers"]["checks"] ?? []) as $name => $check): ?>
            <div class="report-line">
                <span class="tag <?= $check["pass"] ? "tag-pass" : "tag-fail" ?>">
                    [<?= $check["pass"] ? "PASS" : "FAIL" ?>]
                </span>
                <span><strong><?= htmlspecialchars($name) ?>:</strong> <?= htmlspecialchars($check["detail"]) ?></span>
            </div>
        <?php endforeach; ?>
    <?php endif; ?>
<?php endif; ?>

<?php require_once "includes/footer.php"; ?>
