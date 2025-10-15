<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) {
    http_response_code(403);
    echo json_encode(['error' => 'unauthorized'], JSON_THROW_ON_ERROR);
    exit;
}

try {
    $page = isset($_GET['page']) ? (int) $_GET['page'] : 1;
    $page = max(1, $page);

    $pageSize = isset($_GET['pageSize']) ? (int) $_GET['pageSize'] : 10;
    $pageSize = max(1, min(100, $pageSize));

    $offset = ($page - 1) * $pageSize;

    $countStmt = $pdo->query('SELECT COUNT(*) FROM login_logs');
    $total = (int) $countStmt->fetchColumn();

    if ($offset >= $total && $total > 0) {
        $page = (int) max(1, ceil($total / $pageSize));
        $offset = ($page - 1) * $pageSize;
    }

    $logsStmt = $pdo->prepare(
        'SELECT login_logs.id,
                login_logs.login_time,
                login_logs.ip_address,
                login_logs.browser_agent,
                login_logs.status,
                login_logs.risk_score,
                login_logs.risk_decision,
                login_logs.submitted_email,
                login_logs.context_json,
                users.email AS known_email
         FROM login_logs
         LEFT JOIN users ON login_logs.user_id = users.id
         ORDER BY login_logs.login_time DESC
         LIMIT :limit OFFSET :offset'
    );
    $logsStmt->bindValue(':limit', $pageSize, PDO::PARAM_INT);
    $logsStmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $logsStmt->execute();

    $rows = [];
    while ($row = $logsStmt->fetch(PDO::FETCH_ASSOC)) {
        $rows[] = [
            'id' => (int) $row['id'],
            'login_time' => (string) $row['login_time'],
            'ip_address' => (string) $row['ip_address'],
            'browser_agent' => (string) $row['browser_agent'],
            'status' => (string) $row['status'],
            'risk_score' => $row['risk_score'] !== null ? (float) $row['risk_score'] : null,
            'risk_decision' => $row['risk_decision'] !== null ? (string) $row['risk_decision'] : null,
            'submitted_email' => $row['submitted_email'] !== null ? (string) $row['submitted_email'] : null,
            'known_email' => $row['known_email'] !== null ? (string) $row['known_email'] : null,
            'context_json' => $row['context_json'] !== null ? (string) $row['context_json'] : null,
        ];
    }

    $statusCountsStmt = $pdo->query('SELECT status, COUNT(*) AS total FROM login_logs GROUP BY status');
    $statusCounts = ['valid' => 0, 'blocked' => 0, 'verification' => 0];
    while ($row = $statusCountsStmt->fetch(PDO::FETCH_ASSOC)) {
        $status = (string) $row['status'];
        if (isset($statusCounts[$status])) {
            $statusCounts[$status] = (int) $row['total'];
        }
    }

    $lastLoginStmt = $pdo->query('SELECT login_time FROM login_logs ORDER BY login_time DESC LIMIT 1');
    $lastLogin = $lastLoginStmt->fetchColumn();

    echo json_encode([
        'page' => $page,
        'page_size' => $pageSize,
        'total' => $total,
        'total_pages' => $total > 0 ? (int) ceil($total / $pageSize) : 1,
        'data' => $rows,
        'status_counts' => $statusCounts,
        'last_login' => $lastLogin !== false ? (string) $lastLogin : null,
    ], JSON_THROW_ON_ERROR);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        'error' => 'internal_error',
        'message' => $e->getMessage(),
    ], JSON_THROW_ON_ERROR);
}
