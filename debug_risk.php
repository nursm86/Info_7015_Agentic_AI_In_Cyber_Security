<?php
declare(strict_types=1);

require_once __DIR__ . '/risk_scoring.php';

header('Content-Type: application/json');

$features = [
    'attempts_1m_by_ip' => 0,
    'attempts_5m_by_ip' => 0,
    'attempts_1m_by_user' => 0,
    'attempts_5m_by_user' => 0,
    'fail_ratio_10m_by_ip' => 0.0,
    'burst_length_ip' => 1,
    'inter_attempt_ms_ip' => 8000,
    'geo_velocity_user' => 0.0,
    'rtt_ms' => 0,
    'login_success' => 1,
    'ua_family' => 'Chrome',
    'device_type' => 'mobile',
    'country_ip' => 'GA',
    'asn_ip' => 'asn8764',
    'device_seen_before_user' => '0',
    'cookie_seen_before_user' => '0',
];

$response = [
    'scorer_cmd' => SCORER_CMD,
    'result' => null,
    'error' => null,
    'stdout' => null,
    'stderr' => null,
];

$payload = json_encode(['features' => $features], JSON_THROW_ON_ERROR);
$descriptorSpec = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];

$process = proc_open(
    SCORER_CMD,
    $descriptorSpec,
    $pipes,
    __DIR__,
    ['PYTHONPATH' => '', 'PYTHONNOUSERSITE' => '1']
);

if (!is_resource($process)) {
    $response['error'] = 'Failed to start scorer';
} else {
    fwrite($pipes[0], $payload);
    fclose($pipes[0]);

    $response['stdout'] = stream_get_contents($pipes[1]);
    $response['stderr'] = stream_get_contents($pipes[2]);

    fclose($pipes[1]);
    fclose($pipes[2]);

    $exitCode = proc_close($process);
    if ($exitCode !== 0) {
        $response['error'] = 'Scorer exited with code ' . $exitCode;
    } else {
        $response['result'] = json_decode($response['stdout'], true);
    }
}

echo json_encode($response, JSON_PRETTY_PRINT);
