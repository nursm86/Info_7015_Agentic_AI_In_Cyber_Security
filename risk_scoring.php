<?php
declare(strict_types=1);

/**
 * Risk scoring helpers bridging the PHP login flow with the Python RBA model.
 */

const PYTHON_BIN = 'python3';
const SCORE_SCRIPT = __DIR__ . '/model/score_request.py';

/**
 * Build feature vector for the risk model from current request context.
 *
 * @param PDO $pdo
 * @param array{
 *     user_id: ?int,
 *     email: string,
 *     ip: string,
 *     user_agent: string,
 *     device_token: string|null
 * } $ctx
 *
 * @return array<string, int|float|string>
 */
function buildRiskFeatures(PDO $pdo, array $ctx): array
{
    $ip = $ctx['ip'];
    $userId = $ctx['user_id'];
    $email = $ctx['email'];
    $userAgent = $ctx['user_agent'];
    $deviceToken = $ctx['device_token'];

    $deviceType = detectDeviceType($userAgent);
    $uaFamily = extractUaFamily($userAgent);
    $cookieSeen = $deviceToken !== null ? 1 : 0;
    $deviceSeen = 0;

    if ($userId !== null) {
        $deviceSeen = hasUserSeenDevice($pdo, $userId, $userAgent) ? 1 : 0;
    }

    return [
        'attempts_1m_by_ip' => (float) countRecentAttemptsByIp($pdo, $ip, 1),
        'attempts_5m_by_ip' => (float) countRecentAttemptsByIp($pdo, $ip, 5),
        'attempts_1m_by_user' => (float) countRecentAttemptsByUserEmail($pdo, $email, 1),
        'attempts_5m_by_user' => (float) countRecentAttemptsByUserEmail($pdo, $email, 5),
        'fail_ratio_10m_by_ip' => computeFailRatioByIp($pdo, $ip, 10),
        'burst_length_ip' => (float) estimateBurstLength($pdo, $ip),
        'inter_attempt_ms_ip' => estimateInterAttemptMs($pdo, $ip),
        'geo_velocity_user' => 0.0,
        'rtt_ms' => 0.0,
        'login_success' => 0.0,
        'ua_family' => $uaFamily,
        'device_type' => $deviceType,
        'country_ip' => 'ZZ',
        'asn_ip' => 'asn0',
        'device_seen_before_user' => (string) $deviceSeen,
        'cookie_seen_before_user' => (string) $cookieSeen,
    ];
}

function detectDeviceType(string $userAgent): string
{
    $ua = strtolower($userAgent);
    if (str_contains($ua, 'mobile') || str_contains($ua, 'android') || str_contains($ua, 'iphone')) {
        return 'mobile';
    }
    if (str_contains($ua, 'ipad') || str_contains($ua, 'tablet')) {
        return 'tablet';
    }
    if (str_contains($ua, 'windows') || str_contains($ua, 'macintosh') || str_contains($ua, 'linux')) {
        return 'desktop';
    }
    return 'other';
}

function extractUaFamily(string $userAgent): string
{
    if ($userAgent === '') {
        return 'Unknown';
    }
    $parts = preg_split('/\s+/', trim($userAgent));
    if (empty($parts)) {
        return 'Unknown';
    }
    $candidate = preg_replace('/[^A-Za-z]+/', '', (string) $parts[0]);
    return $candidate !== '' ? $candidate : 'Unknown';
}

function hasUserSeenDevice(PDO $pdo, int $userId, string $userAgent): bool
{
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM login_logs WHERE user_id = :user_id AND browser_agent = :agent AND status = "valid"'
    );
    $stmt->execute([
        ':user_id' => $userId,
        ':agent' => $userAgent,
    ]);
    return (int) $stmt->fetchColumn() > 0;
}

function countRecentAttemptsByIp(PDO $pdo, string $ip, int $minutes): int
{
    $minutes = max(1, $minutes);
    $sql = sprintf(
        'SELECT COUNT(*) FROM login_logs WHERE ip_address = :ip AND login_time >= DATE_SUB(NOW(), INTERVAL %d MINUTE)',
        $minutes
    );
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':ip' => $ip]);
    return (int) $stmt->fetchColumn();
}

function countRecentAttemptsByUserEmail(PDO $pdo, string $email, int $minutes): int
{
    if ($email === '') {
        return 0;
    }
    $minutes = max(1, $minutes);
    $sql = sprintf(
        'SELECT COUNT(*) FROM login_logs
         JOIN users ON login_logs.user_id = users.id
         WHERE users.email = :email AND login_time >= DATE_SUB(NOW(), INTERVAL %d MINUTE)',
        $minutes
    );
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':email' => $email]);
    return (int) $stmt->fetchColumn();
}

function computeFailRatioByIp(PDO $pdo, string $ip, int $minutes): float
{
    $minutes = max(1, $minutes);
    $sql = sprintf(
        'SELECT status, COUNT(*) AS total
         FROM login_logs
         WHERE ip_address = :ip AND login_time >= DATE_SUB(NOW(), INTERVAL %d MINUTE)
         GROUP BY status',
        $minutes
    );
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':ip' => $ip]);

    $total = 0;
    $fail = 0;
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $count = (int) $row['total'];
        $total += $count;
        if ($row['status'] !== 'valid') {
            $fail += $count;
        }
    }

    if ($total === 0) {
        return 0.0;
    }
    return (float) ($fail / $total);
}

function estimateBurstLength(PDO $pdo, string $ip): int
{
    $stmt = $pdo->prepare(
        'SELECT login_time FROM login_logs WHERE ip_address = :ip ORDER BY login_time DESC LIMIT 10'
    );
    $stmt->execute([':ip' => $ip]);

    $rows = $stmt->fetchAll(PDO::FETCH_COLUMN);
    if (empty($rows)) {
        return 1;
    }

    $burst = 1;
    $previous = strtotime((string) $rows[0]);
    for ($i = 1, $n = count($rows); $i < $n; $i++) {
        $current = strtotime((string) $rows[$i]);
        if ($current === false || $previous === false) {
            break;
        }

        if (abs($previous - $current) <= 60) {
            $burst++;
        } else {
            break;
        }

        $previous = $current;
    }

    return max(1, $burst);
}

function estimateInterAttemptMs(PDO $pdo, string $ip): float
{
    $stmt = $pdo->prepare(
        'SELECT login_time FROM login_logs WHERE ip_address = :ip ORDER BY login_time DESC LIMIT 1'
    );
    $stmt->execute([':ip' => $ip]);
    $last = $stmt->fetchColumn();

    if ($last === false) {
        return 300000.0; // default to 5 minutes
    }

    $lastTs = strtotime((string) $last);
    if ($lastTs === false) {
        return 300000.0;
    }

    $diff = (time() - $lastTs) * 1000;
    return $diff > 0 ? (float) $diff : 1000.0;
}

/**
 * Call the Python scorer and return the resulting decision.
 *
 * @param array<string, int|float|string> $features
 *
 * @return array{
 *     score: float|null,
 *     decision: string|null,
 *     tau1: float|null,
 *     tau2: float|null
 * }|null
 */
function scoreLoginAttempt(array $features): ?array
{
    if (!is_file(SCORE_SCRIPT)) {
        error_log('[risk_scoring] Score script not found: ' . SCORE_SCRIPT);
        return null;
    }

    $payload = json_encode(['features' => $features], JSON_THROW_ON_ERROR);
    $descriptors = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];

    $cmd = escapeshellcmd(PYTHON_BIN) . ' ' . escapeshellarg(SCORE_SCRIPT);
    $process = proc_open($cmd, $descriptors, $pipes, __DIR__);

    if (!is_resource($process)) {
        error_log('[risk_scoring] Failed to start Python scorer');
        return null;
    }

    fwrite($pipes[0], $payload);
    fclose($pipes[0]);

    $stdout = stream_get_contents($pipes[1]);
    $stderr = stream_get_contents($pipes[2]);

    fclose($pipes[1]);
    fclose($pipes[2]);

    $exitCode = proc_close($process);

    if ($exitCode !== 0) {
        error_log('[risk_scoring] Scorer error: ' . $stderr);
        return null;
    }

    $result = json_decode((string) $stdout, true);
    if (!is_array($result)) {
        error_log('[risk_scoring] Invalid scorer output: ' . $stdout);
        return null;
    }

    return [
        'score' => isset($result['score']) ? (float) $result['score'] : null,
        'decision' => isset($result['decision']) ? (string) $result['decision'] : null,
        'tau1' => isset($result['tau1']) ? (float) $result['tau1'] : null,
        'tau2' => isset($result['tau2']) ? (float) $result['tau2'] : null,
    ];
}
