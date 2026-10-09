<?php
/**
 * SECUREIAM | config/database.php
 * Single PDO connection, shared by all models.
 *
 * SonarQube: no hardcoded credentials.
 * VULNERABLE: $pdo = new PDO('mysql:host=localhost;dbname=secureiam', 'root', 'P@ssw0rd');
 * SECURE:     credentials come from environment variables (set by Podman at runtime).
 * REASON:     secrets in source code end up in Git history and screenshots.
 *             The empty-password fallback is for local XAMPP development only.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

function env_value(string $key, string $default = ''): string
{
    $value = getenv($key);
    return $value === false ? $default : $value;
}

function db(): PDO
{
    static $pdo = null;
    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = sprintf(
        'mysql:host=%s;dbname=%s;charset=utf8mb4',
        env_value('DB_HOST', 'localhost'),
        env_value('DB_NAME', 'secureiam')
    );

    try {
        $pdo = new PDO($dsn, env_value('DB_USER', 'root'), env_value('DB_PASS', ''), [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            // Real prepared statements: the SQL and the data travel separately,
            // so user input can never change the structure of the query.
            PDO::ATTR_EMULATE_PREPARES   => false,
            // All timestamps in UTC so NOW() matches the audit-log display.
            PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4, time_zone = '+00:00'",
        ]);
    } catch (PDOException $e) {
        error_log('DB connection failed: ' . $e->getMessage());
        http_response_code(500);
        exit('Service temporarily unavailable.');
    }
    return $pdo;
}
