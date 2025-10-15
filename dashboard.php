<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: index.php');
    exit;
}

$userStmt = $pdo->prepare('SELECT id, email, created_at FROM users WHERE id = :id LIMIT 1');
$userStmt->execute([':id' => (int) $_SESSION['user_id']]);
$currentUser = $userStmt->fetch();

if (!$currentUser) {
    header('Location: logout.php');
    exit;
}

// Aggregate login log statistics.
$statuses = ['valid' => 0, 'blocked' => 0, 'verification' => 0];
$statsStmt = $pdo->query('SELECT status, COUNT(*) AS total FROM login_logs GROUP BY status');
foreach ($statsStmt as $row) {
    $status = $row['status'];
    if (isset($statuses[$status])) {
        $statuses[$status] = (int) $row['total'];
    }
}

$totalAttempts = array_sum($statuses);
$lastLoginStmt = $pdo->query('SELECT login_time FROM login_logs ORDER BY login_time DESC LIMIT 1');
$lastLogin = $lastLoginStmt->fetchColumn() ?: null;
$lastAttemptText = $lastLogin ? date('M j, Y g:i A', strtotime((string) $lastLogin)) : 'No activity yet';
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard | AI-Protected Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark">
    <div class="container-fluid">
        <a class="navbar-brand fw-semibold" href="#">AI-Protected Dashboard</a>
        <div class="d-flex align-items-center gap-3">
            <span class="text-light small">Signed in as <?= htmlspecialchars($currentUser['email'], ENT_QUOTES, 'UTF-8') ?></span>
            <a class="btn btn-outline-light btn-sm" href="logout.php">Logout</a>
        </div>
    </div>
</nav>

<main class="container py-5">
    <div class="row g-4">
        <div class="col-12 col-lg-4">
            <div class="card shadow-sm h-100">
                <div class="card-body">
                    <h5 class="card-title">Security Overview</h5>
                    <p class="text-muted mb-4">AI-assisted monitoring of login activity.</p>
                    <div class="pb-3">
                        <p class="mb-1 text-secondary">Total attempts</p>
                        <p class="display-6 fw-bold" id="total-attempts"><?= $totalAttempts ?></p>
                    </div>
                    <p class="mb-1 text-secondary">Last attempt</p>
                    <p class="fw-medium" id="last-attempt"><?= htmlspecialchars($lastAttemptText, ENT_QUOTES, 'UTF-8') ?></p>
                    <p class="text-muted small mb-0">Stay vigilant as the AI flags anomalies in real time.</p>
                </div>
            </div>
        </div>
        <div class="col-12 col-lg-8">
            <div class="card shadow-sm h-100">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-start mb-3">
                        <h5 class="card-title mb-0">Login Status Breakdown</h5>
                        <span class="badge bg-primary bg-opacity-75">Live</span>
                    </div>
                    <div class="chart-container">
                        <canvas id="loginChart" data-chart="<?= htmlspecialchars(json_encode($statuses, JSON_HEX_APOS | JSON_HEX_AMP), ENT_QUOTES, 'UTF-8') ?>"></canvas>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div class="row g-4 mt-1">
        <div class="col-12">
            <div class="card shadow-sm">
                <div class="card-body">
                    <h5 class="card-title mb-3">Recent Activity</h5>
                    <div class="d-flex flex-column flex-md-row align-items-md-center justify-content-between gap-3 mb-3">
                        <div class="d-flex align-items-center gap-2">
                            <label for="activity-page-size" class="text-secondary small mb-0">Rows per page</label>
                            <select class="form-select form-select-sm" id="activity-page-size" style="width: auto;">
                                <option value="10" selected>10</option>
                                <option value="25">25</option>
                                <option value="50">50</option>
                            </select>
                        </div>
                        <div class="d-flex align-items-center gap-2 ms-md-auto">
                            <button class="btn btn-outline-secondary btn-sm" type="button" id="activity-prev" disabled>Previous</button>
                            <span class="text-muted small" id="activity-page-info">Page 1 of 1</span>
                            <button class="btn btn-outline-secondary btn-sm" type="button" id="activity-next" disabled>Next</button>
                        </div>
                    </div>
                    <div class="table-responsive">
                        <table class="table align-middle">
                            <thead class="table-light">
                            <tr>
                                <th scope="col">Timestamp</th>
                                <th scope="col">User</th>
                                <th scope="col">IP Address</th>
                                <th scope="col">Browser Agent</th>
                                <th scope="col">Status</th>
                                <th scope="col">Risk</th>
                            </tr>
                            </thead>
                            <tbody id="activity-table-body">
                                <tr>
                                    <td colspan="6" class="text-center text-muted">Loading activity&hellip;</td>
                                </tr>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</main>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.6/dist/chart.umd.min.js"></script>
<script>
    window.chartCounts = <?= json_encode($statuses, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT) ?>;
</script>
<script src="assets/js/dashboard.js"></script>
</body>
</html>
