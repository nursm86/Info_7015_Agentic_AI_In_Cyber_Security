CREATE DATABASE IF NOT EXISTS ai_protected_login
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE ai_protected_login;

CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_logs (
  id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NULL,
  ip_address VARCHAR(45) NOT NULL,
  browser_agent VARCHAR(255) NOT NULL,
  login_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status ENUM('valid', 'blocked', 'verification') NOT NULL,
  risk_score DECIMAL(6,5) NULL,
  risk_decision ENUM('allow', 'step_up', 'block') NULL,
  CONSTRAINT fk_login_logs_user
    FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO users (email, password, created_at)
SELECT 'admin@example.com', '$2y$12$7T56lV4wPvkJeIsA6qyczedXm/seNX6hkQm/uc9Eh8B.9Z7S2OTQK', NOW()
WHERE NOT EXISTS (SELECT 1 FROM users);

INSERT INTO login_logs (user_id, ip_address, browser_agent, login_time, status, risk_score, risk_decision)
SELECT u.id, '127.0.0.1', 'Seeder/1.0', DATE_SUB(NOW(), INTERVAL 2 DAY), 'valid', 0.05000, 'allow'
FROM users u
WHERE NOT EXISTS (SELECT 1 FROM login_logs)
LIMIT 1;

INSERT INTO login_logs (user_id, ip_address, browser_agent, login_time, status, risk_score, risk_decision)
SELECT u.id, '127.0.0.1', 'Seeder/1.0', DATE_SUB(NOW(), INTERVAL 1 DAY), 'blocked', 0.92000, 'block'
FROM users u
WHERE NOT EXISTS (SELECT 1 FROM login_logs WHERE status = 'blocked')
LIMIT 1;

INSERT INTO login_logs (user_id, ip_address, browser_agent, login_time, status, risk_score, risk_decision)
SELECT u.id, '127.0.0.1', 'Seeder/1.0', DATE_SUB(NOW(), INTERVAL 12 HOUR), 'verification', 0.55000, 'step_up'
FROM users u
WHERE NOT EXISTS (SELECT 1 FROM login_logs WHERE status = 'verification')
LIMIT 1;
