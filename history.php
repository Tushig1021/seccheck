<?php
require_once "session_init.php";
require_once "db.php";
$conn = getDbConnection();
$currentUserId = $_SESSION["user_id"];

$conn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
if ($conn->connect_error) {
    die("Database connection failed: " . $conn->connect_error);
}

$stmt = $conn->prepare(
    "SELECT id, url, ssl_score, header_score, total_score, created_at
     FROM diagnoses
     WHERE user_id = ?
     ORDER BY created_at DESC"
);
$stmt->bind_param("i", $currentUserId);
$stmt->execute();
$diagnoses = $stmt->get_result();
?>

<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>SecCheck - History</title>
</head>
<body>
    <h1>Diagnosis History</h1>
    <p><a href="diagnose.php">Run a new diagnosis</a></p>

    <?php if ($diagnoses->num_rows === 0): ?>
        <p>No diagnoses yet.</p>
    <?php else: ?>
        <table border="1" cellpadding="8">
            <tr>
                <th>URL</th>
                <th>SSL Score</th>
                <th>Header Score</th>
                <th>Total Score</th>
                <th>Date</th>
            </tr>
            <?php while ($row = $diagnoses->fetch_assoc()): ?>
                <tr>
                    <td><?= htmlspecialchars($row["url"]) ?></td>
                    <td><?= htmlspecialchars($row["ssl_score"]) ?></td>
                    <td><?= htmlspecialchars($row["header_score"]) ?></td>
                    <td><?= htmlspecialchars($row["total_score"]) ?></td>
                    <td><?= htmlspecialchars($row["created_at"]) ?></td>
                </tr>
            <?php endwhile; ?>
        </table>
    <?php endif; ?>
</body>
</html>
