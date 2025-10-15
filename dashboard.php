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

$recentStmt = $pdo->prepare(
    'SELECT login_logs.login_time,
            login_logs.ip_address,
            login_logs.browser_agent,
            login_logs.status,
            login_logs.risk_score,
            login_logs.risk_decision,
            users.email
     FROM login_logs
     LEFT JOIN users ON login_logs.user_id = users.id
     ORDER BY login_logs.login_time DESC
     LIMIT 8'
);
$recentStmt->execute();
$recentLogs = $recentStmt->fetchAll();

$totalAttempts = array_sum($statuses);
$lastLogin = $recentLogs[0]['login_time'] ?? null;
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
                        <p class="display-6 fw-bold"><?= $totalAttempts ?></p>
                    </div>
                    <p class="mb-1 text-secondary">Last attempt</p>
                    <p class="fw-medium"><?= $lastLogin ? date('M j, Y g:i A', strtotime($lastLogin)) : 'No activity yet' ?></p>
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
                            <tbody>
                            <?php if (empty($recentLogs)): ?>
                                <tr>
                                    <td colspan="6" class="text-center text-muted">No login activity recorded yet.</td>
                                </tr>
                            <?php else: ?>
                                <?php foreach ($recentLogs as $log): ?>
                                    <tr>
                                        <td><?= date('M j, Y g:i A', strtotime($log['login_time'])) ?></td>
                                        <td><?= htmlspecialchars($log['email'] ?? 'Unknown user', ENT_QUOTES, 'UTF-8') ?></td>
                                        <td><?= htmlspecialchars($log['ip_address'], ENT_QUOTES, 'UTF-8') ?></td>
                                        <td>
                                            <span class="d-inline-block text-truncate" style="max-width: 220px;"
                                                  title="<?= htmlspecialchars($log['browser_agent'], ENT_QUOTES, 'UTF-8') ?>">
                                                <?= htmlspecialchars($log['browser_agent'], ENT_QUOTES, 'UTF-8') ?>
                                            </span>
                                        </td>
                                        <td>
                                            <span class="badge bg-<?= $log['status'] === 'valid' ? 'success' : ($log['status'] === 'blocked' ? 'danger' : 'warning') ?>">
                                                <?= ucfirst($log['status']) ?>
                                            </span>
                                        </td>
                                        <td>
                                            <?php if ($log['risk_score'] !== null): ?>
                                                <div class="d-flex flex-column small">
                                                    <span><?= number_format((float) $log['risk_score'], 3) ?></span>
                                                    <span class="text-muted"><?= htmlspecialchars($log['risk_decision'] ?? 'n/a', ENT_QUOTES, 'UTF-8') ?></span>
                                                </div>
                                            <?php else: ?>
                                                <span class="text-muted small">n/a</span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            <?php endif; ?>
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
