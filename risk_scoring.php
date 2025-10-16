<?php
declare(strict_types=1);

/**
 * Risk scoring helpers bridging the PHP login flow with the Python RBA model.
 */

$scorerCmd = getenv('RBA_SCORER_CMD');
if ($scorerCmd === false || trim((string) $scorerCmd) === '') {
    $wrapper = __DIR__ . '/model/run_scorer.sh';
    if (is_file($wrapper) && is_executable($wrapper)) {
        $scorerCmd = escapeshellarg($wrapper);
    } else {
        $python = '/Library/Developer/CommandLineTools/usr/bin/python3';
        if (!is_executable($python)) {
            $python = '/usr/bin/python3';
        }
        $scorerCmd = escapeshellcmd('/usr/bin/arch') . ' -x86_64 ' . escapeshellarg($python) . ' ' . escapeshellarg(__DIR__ . '/model/score_request.py');
    }
} else {
    $scorerCmd = trim((string) $scorerCmd);
}

define('SCORER_CMD', $scorerCmd);
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
    [$deviceSeen, $cookieSeen] = computeSeenFlags($pdo, $userId, $userAgent, $deviceToken);
    $countryCode = detectCountryCode();
    $asnCode = estimateAsn($ip);

    return [
        'attempts_30s_by_ip' => (float) countRecentAttemptsByIpSeconds($pdo, $ip, 30),
        'attempts_30s_total' => (float) countRecentAttemptsTotalSeconds($pdo, 30),
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
        'country_ip' => $countryCode,
        'asn_ip' => $asnCode,
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

function computeSeenFlags(PDO $pdo, ?int $userId, string $userAgent, ?string $deviceToken): array
{
    $deviceSeen = 0;
    $cookieSeen = 0;

    if ($userId === null) {
        return [$deviceSeen, $cookieSeen];
    }

    if (hasUserSeenDevice($pdo, $userId, $userAgent)) {
        $deviceSeen = 1;
    }

    if ($deviceToken !== null && $deviceToken !== '') {
        if (hasUserSeenCookie($pdo, $userId, $deviceToken)) {
            $cookieSeen = 1;
        }
    }

    return [$deviceSeen, $cookieSeen];
}

function hasUserSeenDevice(PDO $pdo, int $userId, string $userAgent): bool
{
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) FROM login_logs WHERE user_id = :user_id AND browser_agent = :agent'
    );
    $stmt->execute([
        ':user_id' => $userId,
        ':agent' => $userAgent,
    ]);
    if ((int) $stmt->fetchColumn() > 0) {
        return true;
    }

    $contextStmt = $pdo->prepare(
        'SELECT context_json FROM login_logs WHERE user_id = :user_id AND context_json IS NOT NULL ORDER BY login_time DESC LIMIT 25'
    );
    $contextStmt->execute([':user_id' => $userId]);
    while ($row = $contextStmt->fetch(PDO::FETCH_ASSOC)) {
        $context = json_decode((string) $row['context_json'], true);
        if (!is_array($context)) {
            continue;
        }
        $ctxAgent = $context['user_agent'] ?? null;
        if ($ctxAgent !== null && strcasecmp((string) $ctxAgent, $userAgent) === 0) {
            return true;
        }
        $features = $context['features'] ?? null;
        if (is_array($features) && isset($features['ua_family'])) {
            $ua = extractUaFamily($userAgent);
            if (strcasecmp((string) $features['ua_family'], $ua) === 0) {
                return true;
            }
        }
    }

    return false;
}

function hasUserSeenCookie(PDO $pdo, int $userId, string $deviceToken): bool
{
    $stmt = $pdo->prepare(
        'SELECT context_json FROM login_logs WHERE user_id = :user_id AND context_json IS NOT NULL ORDER BY login_time DESC LIMIT 50'
    );
    $stmt->execute([':user_id' => $userId]);
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        $context = json_decode((string) $row['context_json'], true);
        if (!is_array($context)) {
            continue;
        }
        $loggedToken = $context['device_token'] ?? ($context['features']['device_token'] ?? null);
        if ($loggedToken !== null && hash_equals((string) $loggedToken, $deviceToken)) {
            return true;
        }
    }
    return false;
}

function detectCountryCode(): string
{
    $candidates = [
        $_SERVER['HTTP_CF_IPCOUNTRY'] ?? '',
        $_SERVER['GEOIP_COUNTRY_CODE'] ?? '',
        $_SERVER['HTTP_X_APPENGINE_COUNTRY'] ?? '',
    ];

    foreach ($candidates as $candidate) {
        $code = normalizeCountryCode($candidate);
        if ($code !== null) {
            return $code;
        }
    }

    $acceptLanguage = $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '';
    if ($acceptLanguage !== '') {
        $parts = explode(',', $acceptLanguage);
        foreach ($parts as $part) {
            if (preg_match('/([a-zA-Z]{2})(?:[_-]([a-zA-Z]{2}))?/', $part, $matches)) {
                $country = $matches[2] ?? $matches[1];
                $code = normalizeCountryCode($country);
                if ($code !== null) {
                    return $code;
                }
            }
        }
    }

    return 'ZZ';
}

function normalizeCountryCode(string $value): ?string
{
    $value = strtoupper(trim($value));
    if ($value === '') {
        return null;
    }
    if (strlen($value) === 2 && ctype_alpha($value)) {
        return $value;
    }
    return null;
}

function estimateAsn(string $ip): string
{
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return 'asn0';
    }

    $normalized = strtolower($ip);
    $hash = sprintf('%u', crc32($normalized));
    $number = (int) $hash % 10000;
    return 'asn' . $number;
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

function countRecentAttemptsByIpSeconds(PDO $pdo, string $ip, int $seconds): int
{
    $seconds = max(1, $seconds);
    $sql = sprintf(
        'SELECT COUNT(*) FROM login_logs WHERE ip_address = :ip AND login_time >= DATE_SUB(NOW(), INTERVAL %d SECOND)',
        $seconds
    );
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':ip' => $ip]);
    return (int) $stmt->fetchColumn();
}

function countRecentAttemptsTotalSeconds(PDO $pdo, int $seconds): int
{
    $seconds = max(1, $seconds);
    $sql = sprintf(
        'SELECT COUNT(*) FROM login_logs WHERE login_time >= DATE_SUB(NOW(), INTERVAL %d SECOND)',
        $seconds
    );
    $stmt = $pdo->prepare($sql);
    $stmt->execute();
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
 *     tau2: float|null,
 *     reason: string|null
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

    $process = proc_open(
        SCORER_CMD,
        $descriptors,
        $pipes,
        __DIR__,
        [
            'PYTHONPATH' => '',
            'PYTHONNOUSERSITE' => '1',
        ]
    );

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

    $baseResult = [
        'score' => isset($result['score']) ? (float) $result['score'] : null,
        'decision' => isset($result['decision']) ? (string) $result['decision'] : null,
        'tau1' => isset($result['tau1']) ? (float) $result['tau1'] : null,
        'tau2' => isset($result['tau2']) ? (float) $result['tau2'] : null,
    ];

    if (!array_key_exists('reason', $baseResult)) {
        $baseResult['reason'] = null;
    }

    // Comment out the next block if you want to disable the Ollama augmentation layer.
    $augmented = augmentRiskDecisionWithOllama($features, $baseResult);
    if (is_array($augmented)) {
        return $augmented;
    }

    return $baseResult;
}

/**
 * Enrich the base scorer decision using a local Ollama model (e.g. phi-3.5).
 *
 * @param array<string, int|float|string> $features
 * @param array{score: float|null, decision: string|null, tau1: float|null, tau2: float|null, reason: string|null} $baseResult
 *
 * @return array{score: float|null, decision: string|null, tau1: float|null, tau2: float|null, reason: string|null}|null
 */
function augmentRiskDecisionWithOllama(array $features, array $baseResult): ?array
{
    $model = trim((string) (getenv('OLLAMA_RISK_MODEL') ?: 'phi3.5:latest'));
    if ($model === '') {
        return null;
    }

    if (!function_exists('curl_init')) {
        error_log('[risk_scoring] Ollama integration requires the PHP cURL extension.');
        return null;
    }

    $endpoint = trim((string) (getenv('OLLAMA_HOST') ?: 'http://127.0.0.1:11434'));
    $url = rtrim($endpoint, '/') . '/api/generate';

    $prompt = buildOllamaPrompt($features, $baseResult);
    try {
        $payload = json_encode([
            'model' => $model,
            'prompt' => $prompt,
            'format' => 'json',
            'stream' => false,
            'options' => [
                'temperature' => 0.0,
                'num_predict' => 200,
            ],
        ], JSON_THROW_ON_ERROR);
    } catch (\JsonException $e) {
        error_log('[risk_scoring] Failed to encode Ollama payload: ' . $e->getMessage());
        return null;
    }

    $ch = curl_init($url);
    if ($ch === false) {
        error_log('[risk_scoring] Failed to init curl handle for Ollama.');
        return null;
    }

    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_TIMEOUT => 25,
    ]);

    $body = curl_exec($ch);
    if ($body === false) {
        $err = curl_error($ch);
        curl_close($ch);
        error_log('[risk_scoring] Ollama request failed: ' . $err);
        return null;
    }

    $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    $decoded = json_decode($body, true);
    if ($status < 200 || $status >= 300) {
        $message = is_array($decoded) && isset($decoded['error']) ? (string) $decoded['error'] : $body;
        error_log('[risk_scoring] Ollama returned HTTP ' . $status . ': ' . $message);
        return null;
    }

    if (!is_array($decoded)) {
        error_log('[risk_scoring] Ollama response not valid JSON: ' . $body);
        return null;
    }

    $responsePayload = null;
    if (isset($decoded['response']) && is_string($decoded['response'])) {
        $responsePayload = trim($decoded['response']);
    } elseif (isset($decoded['message']['content']) && is_string($decoded['message']['content'])) {
        $responsePayload = trim($decoded['message']['content']);
    }

    if ($responsePayload === null || $responsePayload === '') {
        error_log('[risk_scoring] Ollama response missing content.');
        return null;
    }

    $parsed = json_decode($responsePayload, true);
    if (!is_array($parsed)) {
        error_log('[risk_scoring] Ollama decision payload invalid: ' . $responsePayload);
        return null;
    }

    $augmented = $baseResult;

    if (array_key_exists('score', $parsed)) {
        $augmented['score'] = is_numeric($parsed['score']) ? (float) $parsed['score'] : $augmented['score'];
    }

    if (array_key_exists('tau1', $parsed)) {
        $augmented['tau1'] = is_numeric($parsed['tau1']) ? (float) $parsed['tau1'] : $augmented['tau1'];
    }

    if (array_key_exists('tau2', $parsed)) {
        $augmented['tau2'] = is_numeric($parsed['tau2']) ? (float) $parsed['tau2'] : $augmented['tau2'];
    }

    if (isset($parsed['decision'])) {
        $candidate = strtolower((string) $parsed['decision']);
        $allowed = ['allow', 'step_up', 'block'];
        if (in_array($candidate, $allowed, true)) {
            $augmented['decision'] = $candidate;
        }
    }

    if (isset($parsed['reason'])) {
        $candidateReason = trim((string) $parsed['reason']);
        if ($candidateReason !== '') {
            $augmented['reason'] = $candidateReason;
        }
    } else {
        $augmented['reason'] = $augmented['reason'] ?? 'No explanation provided.';
    }

    return $augmented;
}

/**
 * Craft the prompt instructing the local Ollama model how to judge the login attempt.
 *
 * @param array<string, int|float|string> $features
 * @param array{score: float|null, decision: string|null, tau1: float|null, tau2: float|null, reason: string|null} $baseResult
 */
function buildOllamaPrompt(array $features, array $baseResult): string
{
    try {
        $featureJson = json_encode($features, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $baseJson = json_encode($baseResult, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    } catch (\JsonException $e) {
        $featureJson = '{}';
        $baseJson = '{}';
    }

    $instructions = <<<PROMPT
You are an AI security analyst helping to detect suspicious login attempts. Review the engineered login features and the baseline model verdict. \
Focus on signals that could indicate attack conditions such as rapid bursts of attempts, unusual IP behavior, or unseen devices. \
Decide whether to allow, step up, or block the attempt.

You MUST reply with EXACT JSON (no markdown, no code fences, no prose) in this structure:
{
  "score": <float 0-1>,
  "decision": "allow"|"step_up"|"block",
  "tau1": <float 0-1>,
  "tau2": <float 0-1>,
  "reason": "<short justification>"
}
- Keep tau1 <= tau2.
- If you keep the baseline score, repeat it exactly; otherwise provide your adjusted value.
- "reason" must be a concise sentence citing the strongest evidence.

Baseline model result:
$baseJson

Engineered features:
$featureJson
PROMPT;

    return $instructions;
}
