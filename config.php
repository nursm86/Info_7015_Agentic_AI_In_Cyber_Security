<?php
declare(strict_types=1);

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

const DB_HOST = 'localhost';
const DB_NAME = 'ai_protected_login';
const DB_USER = 'root';
const DB_PASS = '';

try {
    $pdo = new PDO(
        'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=utf8mb4',
        DB_USER,
        DB_PASS,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
} catch (PDOException $e) {
    exit('Database connection failed: ' . $e->getMessage());
}

/**
 * Insert baseline records to ensure the project has data to work with.
 */
function seedDatabase(PDO $pdo): void
{
    try {
        $userCount = (int) $pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
        if ($userCount === 0) {
            $insertUser = $pdo->prepare(
                'INSERT INTO users (email, password, created_at) VALUES (:email, :password, NOW())'
            );
            $insertUser->execute([
                ':email' => 'admin@example.com',
                ':password' => password_hash('Password123!', PASSWORD_DEFAULT),
            ]);
        }

        $logCount = (int) $pdo->query('SELECT COUNT(*) FROM login_logs')->fetchColumn();
        if ($logCount === 0) {
            $userId = (int) $pdo->query('SELECT id FROM users LIMIT 1')->fetchColumn();
            $insertLog = $pdo->prepare(
                'INSERT INTO login_logs (user_id, ip_address, browser_agent, login_time, status, risk_score, risk_decision)
                 VALUES (:user_id, :ip, :agent, :time, :status, :risk_score, :risk_decision)'
            );

            $seedLogs = [
                ['status' => 'valid', 'decision' => 'allow', 'score' => 0.05, 'time' => date('Y-m-d H:i:s', strtotime('-2 days'))],
                ['status' => 'blocked', 'decision' => 'block', 'score' => 0.92, 'time' => date('Y-m-d H:i:s', strtotime('-1 day'))],
                ['status' => 'verification', 'decision' => 'step_up', 'score' => 0.55, 'time' => date('Y-m-d H:i:s', strtotime('-12 hours'))],
            ];

            foreach ($seedLogs as $entry) {
                $insertLog->execute([
                    ':user_id' => $userId,
                    ':ip' => '127.0.0.1',
                    ':agent' => 'Seeder/1.0',
                    ':time' => $entry['time'],
                    ':status' => $entry['status'],
                    ':risk_score' => $entry['score'],
                    ':risk_decision' => $entry['decision'],
                ]);
            }
        }
    } catch (PDOException $e) {
        // Tables might not be ready yet; fail silently to avoid breaking the app.
    }
}

seedDatabase($pdo);

/**
 * Record a login attempt into the audit trail.
 */
function logLoginAttempt(
    PDO $pdo,
    ?int $userId,
    string $ipAddress,
    string $browserAgent,
    string $status,
    ?float $riskScore = null,
    ?string $riskDecision = null
): void {
    $stmt = $pdo->prepare(
        'INSERT INTO login_logs (user_id, ip_address, browser_agent, login_time, status, risk_score, risk_decision)
         VALUES (:user_id, :ip, :agent, NOW(), :status, :risk_score, :risk_decision)'
    );
    $stmt->execute([
        ':user_id' => $userId,
        ':ip' => $ipAddress,
        ':agent' => $browserAgent,
        ':status' => $status,
        ':risk_score' => $riskScore,
        ':risk_decision' => $riskDecision,
    ]);
}

/**
 * Retrieve the client IP address in a best-effort way.
 */
function getClientIp(): string
{
    $keys = [
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'REMOTE_ADDR',
    ];

    foreach ($keys as $key) {
        if (!empty($_SERVER[$key])) {
            $value = explode(',', (string) $_SERVER[$key]);
            return trim($value[0]);
        }
    }

    return '0.0.0.0';
}

/**
 * Attempt to authenticate a persistent session cookie.
 */
function bootstrapRememberedUser(PDO $pdo): void
{
    if (isset($_SESSION['user_id']) || empty($_COOKIE['remember_me'])) {
        return;
    }

    $decoded = base64_decode($_COOKIE['remember_me'], true);
    if ($decoded === false || !str_contains($decoded, ':')) {
        setcookie('remember_me', '', time() - 3600, '/', '', false, true);
        return;
    }

    [$userId, $token] = explode(':', $decoded, 2);
    if (!ctype_digit($userId) || empty($token)) {
        setcookie('remember_me', '', time() - 3600, '/', '', false, true);
        return;
    }

    $stmt = $pdo->prepare('SELECT id, email, password FROM users WHERE id = :id LIMIT 1');
    $stmt->execute([':id' => (int) $userId]);
    $user = $stmt->fetch();

    if (!$user) {
        setcookie('remember_me', '', time() - 3600, '/', '', false, true);
        return;
    }

    $expected = hash_hmac('sha256', $user['email'], $user['password']);
    if (hash_equals($expected, $token)) {
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int) $user['id'];
    } else {
        setcookie('remember_me', '', time() - 3600, '/', '', false, true);
    }
}

bootstrapRememberedUser($pdo);
