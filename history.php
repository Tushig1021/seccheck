<?php
require_once "session_init.php";
require_once "db.php";

if (!isset($_SESSION["user_id"])) {
    header("Location: login.php");
    exit;
}

$currentUserId = $_SESSION["user_id"];
$conn = getDbConnection();

$stmt = $conn->prepare(
    "SELECT id, url, ssl_score, header_score, total_score, created_at
     FROM diagnoses
     WHERE user_id = ?
     ORDER BY created_at DESC"
);
$stmt->bind_param("i", $currentUserId);
$stmt->execute();
$diagnoses = $stmt->get_result();

$pageTitle = "History";
require_once "includes/header.php";
?>

<h1>history</h1>

<?php if ($diagnoses->num_rows === 0): ?>
    <p style="color: var(--text-dim);">no scans yet — <a href="diagnose.php">run your first one</a></p>
<?php else: ?>
    <table>
        <tr>
            <th>url</th>
            <th>ssl</th>
            <th>headers</th>
            <th>total</th>
            <th>date</th>
        </tr>
        <?php while ($row = $diagnoses->fetch_assoc()): ?>
            <tr>
                <td><?= htmlspecialchars($row["url"]) ?></td>
                <td><?= htmlspecialchars($row["ssl_score"]) ?></td>
                <td><?= htmlspecialchars($row["header_score"]) ?></td>
                <td><?= htmlspecialchars($row["total_score"]) ?></td>
                <td style="color: var(--text-dim);"><?= htmlspecialchars($row["created_at"]) ?></td>
            </tr>
        <?php endwhile; ?>
    </table>
<?php endif; ?>

<?php require_once "includes/footer.php"; ?>
