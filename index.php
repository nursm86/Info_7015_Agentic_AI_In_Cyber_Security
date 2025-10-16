<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/risk_scoring.php';

if (isset($_SESSION['user_id'])) {
    header('Location: dashboard.php');
    exit;
}

$error = '';
$email = '';
$deviceToken = $_COOKIE['device_token'] ?? null;
$requireOtp = false;
$otpError = '';
$pendingStepUp = $_SESSION['pending_step_up'] ?? null;

if ($deviceToken === null) {
    try {
        $deviceToken = bin2hex(random_bytes(16));
        setcookie('device_token', $deviceToken, time() + (86400 * 365), '/', '', false, true);
    } catch (Exception $e) {
        $deviceToken = null;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['otp_verification'])) {
        $otpCode = trim((string) ($_POST['otp_code'] ?? ''));

        if (!$pendingStepUp) {
            $error = 'Your verification session expired. Please sign in again.';
        } elseif ($otpCode !== '89632') {
            $otpError = 'Invalid verification code. Please try again.';
            $requireOtp = true;
        } else {
            $otpContext = $pendingStepUp;
            $stepUserStmt = $pdo->prepare('SELECT id, email, password FROM users WHERE id = :id LIMIT 1');
            $stepUserStmt->execute([':id' => (int) $otpContext['user_id']]);
            $stepUser = $stepUserStmt->fetch();

            if (!$stepUser) {
                $error = 'Account no longer available. Please sign in again.';
                unset($_SESSION['pending_step_up']);
                $pendingStepUp = null;
            } else {
                session_regenerate_id(true);
                $_SESSION['user_id'] = (int) $stepUser['id'];

                if (!empty($otpContext['remember'])) {
                    $token = hash_hmac('sha256', $stepUser['email'], $stepUser['password']);
                    $value = base64_encode($stepUser['id'] . ':' . $token);
                    setcookie('remember_me', $value, time() + (86400 * 7), '/', '', false, true);
                } else {
                    setcookie('remember_me', '', time() - 3600, '/', '', false, true);
                }

                $finalContext = $otpContext['attempt_context'] ?? [];
                $finalContext['step_up'] = array_merge(
                    $finalContext['step_up'] ?? [],
                    ['verified' => true, 'method' => 'static_code']
                );
                $finalContext['auth'] = [
                    'status' => 'success',
                    'user_id' => (int) $stepUser['id'],
                    'step_up_verified' => true,
                ];

                logLoginAttempt(
                    $pdo,
                    (int) $otpContext['user_id'],
                    (string) $otpContext['ip_address'],
                    (string) $otpContext['user_agent'],
                    'valid',
                    $otpContext['risk_score'] ?? null,
                    $otpContext['risk_decision'] ?? null,
                    $otpContext['submitted_email'] ?? null,
                    $finalContext
                );

                unset($_SESSION['pending_step_up']);
                header('Location: dashboard.php');
                exit;
            }
        }
    } else {
        unset($_SESSION['pending_step_up']);
        $pendingStepUp = null;

        $email = trim((string) ($_POST['email'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $remember = isset($_POST['remember']);

        if ($email === '' || $password === '') {
            $error = 'Please provide both email and password.';
        } else {
            $stmt = $pdo->prepare('SELECT id, email, password FROM users WHERE email = :email LIMIT 1');
            $stmt->execute([':email' => $email]);
            $user = $stmt->fetch();
            $userId = $user ? (int) $user['id'] : null;
            $passwordValid = $user && password_verify($password, $user['password']);

            $ipAddress = getClientIp();
            $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

            $riskScore = null;
            $riskDecision = null;
            $attemptContext = [
                'submitted_email' => $email,
                'ip_address' => $ipAddress,
                'user_agent' => $userAgent,
                'device_token' => $deviceToken,
                'remember_me' => $remember,
            ];

            try {
                $features = buildRiskFeatures($pdo, [
                    'user_id' => $userId,
                    'email' => $email,
                    'ip' => $ipAddress,
                    'user_agent' => $userAgent,
                    'device_token' => $deviceToken,
                ]);
                $attemptContext['features'] = $features;
                $riskResult = scoreLoginAttempt($features);
                if (is_array($riskResult)) {
                    $riskScore = $riskResult['score'];
                    $riskDecision = $riskResult['decision'];
                    $attemptContext['risk'] = $riskResult;
                }
            } catch (Throwable $t) {
                error_log('[login] Risk scoring failed: ' . $t->getMessage());
                $attemptContext['risk_error'] = $t->getMessage();
            }

            $processPassword = true;

            if ($riskDecision === 'block') {
                $error = 'Access temporarily blocked by AI risk controls. Please try again later.';
                logLoginAttempt(
                    $pdo,
                    $userId,
                    $ipAddress,
                    $userAgent,
                    'blocked',
                    $riskScore,
                    $riskDecision,
                    $email !== '' ? $email : null,
                    $attemptContext
                );
                $processPassword = false;
            } elseif ($riskDecision === 'step_up') {
                if (!$passwordValid) {
                    // treat as an invalid password attempt even if the model requested step-up
                    $attemptContext['auth'] = ['status' => 'invalid_password', 'step_up' => true];
                } else {
                    $requireOtp = true;
                    $attemptContext['step_up'] = ['required' => true, 'method' => 'static_code'];
                    $_SESSION['pending_step_up'] = [
                        'user_id' => $userId,
                        'email' => $user['email'] ?? $email,
                        'remember' => $remember,
                        'risk_score' => $riskScore,
                        'risk_decision' => $riskDecision,
                        'attempt_context' => $attemptContext,
                        'ip_address' => $ipAddress,
                        'user_agent' => $userAgent,
                        'submitted_email' => $email !== '' ? $email : null,
                    ];
                    $pendingStepUp = $_SESSION['pending_step_up'];
                    $processPassword = false;
                }
            } elseif ($riskDecision === null && $riskScore === null) {
                // scorer unavailable, default to allow path but note missing telemetry
                $riskDecision = 'allow';
            }

            if ($processPassword) {
                if ($passwordValid) {
                    session_regenerate_id(true);
                    $_SESSION['user_id'] = (int) $user['id'];

                    if ($remember) {
                        $token = hash_hmac('sha256', $user['email'], $user['password']);
                        $value = base64_encode($user['id'] . ':' . $token);
                        setcookie('remember_me', $value, time() + (86400 * 7), '/', '', false, true);
                    } else {
                        setcookie('remember_me', '', time() - 3600, '/', '', false, true);
                    }

                    $attemptContext['auth'] = ['status' => 'success', 'user_id' => (int) $user['id']];
                    logLoginAttempt(
                        $pdo,
                        $userId,
                        $ipAddress,
                        $userAgent,
                        'valid',
                        $riskScore,
                        $riskDecision,
                        $email !== '' ? $email : null,
                        $attemptContext
                    );
                    header('Location: dashboard.php');
                    exit;
                }

                $error = 'Invalid email or password.';
                $attemptContext['auth'] = $attemptContext['auth'] ?? ['status' => 'invalid_password'];
                logLoginAttempt(
                    $pdo,
                    $userId,
                    $ipAddress,
                    $userAgent,
                    'blocked',
                    $riskScore,
                    $riskDecision,
                    $email !== '' ? $email : null,
                    $attemptContext
                );
            }
        }
    }
} elseif ($pendingStepUp) {
    $requireOtp = true;
    $email = $pendingStepUp['submitted_email'] ?? $email;
}
$rememberChecked = isset($_POST['remember']) || (!empty($pendingStepUp) && !empty($pendingStepUp['remember']));
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>AI-Protected Login Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="bg-light min-vh-100 d-flex align-items-center">
<main class="container">
    <div class="row justify-content-center">
        <div class="col-md-6 col-lg-5">
            <div class="card shadow-sm border-0">
                <div class="card-body p-5">
                    <div class="text-center mb-4">
                        <h1 class="h3 fw-bold">AI-Protected Access</h1>
                        <p class="text-muted mb-0">Secure your session with intelligent monitoring.</p>
                    </div>
                    <?php if ($error !== ''): ?>
                        <div class="alert alert-danger" role="alert">
                            <?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?>
                        </div>
                    <?php endif; ?>
                    <form method="post" novalidate>
                        <div class="mb-3">
                            <label for="email" class="form-label">Email address</label>
                            <div class="input-group">
                                <span class="input-group-text">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
                                         class="bi bi-envelope" viewBox="0 0 16 16" aria-hidden="true">
                                        <path
                                            d="M0 4a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2zm2-1a1 1 0 0 0-1 1v.217l7 4.2 7-4.2V4a1 1 0 0 0-1-1z"/>
                                        <path
                                            d="m0 6.383 5.803 3.482L0 13.118zM10.197 9.865 16 13.118l-5.803-3.753z"/>
                                    </svg>
                                </span>
                                <input type="email"
                                       class="form-control"
                                       id="email"
                                       name="email"
                                       value="<?= htmlspecialchars($email, ENT_QUOTES, 'UTF-8') ?>"
                                       placeholder="name@example.com"
                                       required>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <div class="input-group">
                                <span class="input-group-text">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
                                         class="bi bi-shield-lock" viewBox="0 0 16 16" aria-hidden="true">
                                        <path d="M5.5 9.5a1.5 1.5 0 1 1 3 0 1.5 1.5 0 0 1-3 0"/>
                                        <path
                                            d="M7.467.133a1 1 0 0 1 1.066 0l5.5 3.182a1 1 0 0 1 .5.866v4.906c0 3.423-2.548 6.55-6.432 7.839a1 1 0 0 1-.668 0C3.548 15.637 1 12.51 1 9.087V4.181a1 1 0 0 1 .5-.866zM8 1.134 2 4.316v4.77c0 2.917 2.16 5.57 5.538 6.676C10.916 14.656 13 12.003 13 9.087v-4.77z"/>
                                    </svg>
                                </span>
                                <input type="password"
                                       class="form-control"
                                       id="password"
                                       name="password"
                                       placeholder="Your secure password"
                                       required>
                            </div>
                        </div>
                        <div class="d-flex justify-content-between align-items-center mb-4">
                            <div class="form-check">
                                <input class="form-check-input" type="checkbox" value="1" id="remember" name="remember" <?= $rememberChecked ? 'checked' : '' ?>>
                                <label class="form-check-label" for="remember">
                                    Remember me
                                </label>
                            </div>
                            <span class="text-muted small">Monitored by AI security heuristics.</span>
                        </div>
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary btn-lg">
                                Sign in securely
                            </button>
                        </div>
                    </form>
                </div>
                <div class="card-footer text-center text-muted small">
                    &copy; <?= date('Y') ?> AI-Protected Login Dashboard
                </div>
            </div>
        </div>
    </div>
</main>
<div class="modal fade" id="otpModal" tabindex="-1" aria-labelledby="otpModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="otpModalLabel">Additional Verification</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <p class="text-muted mb-3">
                    An extra verification step is required. Enter the one-time code sent by the security system to continue.
                </p>
                <?php if ($otpError !== ''): ?>
                    <div class="alert alert-danger py-2" role="alert">
                        <?= htmlspecialchars($otpError, ENT_QUOTES, 'UTF-8') ?>
                    </div>
                <?php endif; ?>
                <form method="post" id="otpForm" class="needs-validation" novalidate>
                    <input type="hidden" name="otp_verification" value="1">
                    <div class="mb-3">
                        <label for="otp_code" class="form-label">Verification code</label>
                        <input type="text"
                               class="form-control"
                               id="otp_code"
                               name="otp_code"
                               pattern="\d{5}"
                               inputmode="numeric"
                               autocomplete="one-time-code"
                               required>
                        <div class="form-text">Enter the 5-digit code to finalize sign-in.</div>
                        <div class="invalid-feedback">Please enter the 5-digit verification code.</div>
                    </div>
                    <div class="d-grid">
                        <button type="submit" class="btn btn-primary">Verify and continue</button>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
<script>
    (function () {
        'use strict';
        const otpModalEl = document.getElementById('otpModal');
        const otpShouldShow = <?= $requireOtp ? 'true' : 'false' ?>;
        if (otpShouldShow && otpModalEl) {
            const otpModal = new bootstrap.Modal(otpModalEl, {backdrop: 'static', keyboard: false});
            otpModal.show();
            const otpInput = document.getElementById('otp_code');
            if (otpInput) {
                otpInput.focus();
            }
        }

        const otpForm = document.getElementById('otpForm');
        if (otpForm) {
            otpForm.addEventListener('submit', (event) => {
                if (!otpForm.checkValidity()) {
                    event.preventDefault();
                    event.stopPropagation();
                }
                otpForm.classList.add('was-validated');
            }, false);
        }
    })();
</script>
</body>
</html>
