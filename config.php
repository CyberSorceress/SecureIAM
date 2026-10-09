<?php
/**
 * SECUREIAM | config/config.php
 * Application constants. Nothing secret lives here: secrets come from
 * environment variables (see config/database.php).
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

define('APP_NAME', 'SecureIAM');
define('COMPANY_NAME', 'TechNova');

// ---- Security policy (change here, effective everywhere) ----
define('SESSION_TIMEOUT', 900);        // idle timeout: 15 minutes
define('MAX_FAILED_ATTEMPTS', 5);      // lock account after 5 wrong passwords
define('LOCKOUT_MINUTES', 15);         // lock duration
define('RESET_TOKEN_MINUTES', 30);     // password-reset link lifetime
define('MIN_PASSWORD_LENGTH', 10);
define('MAX_PASSWORD_LENGTH', 72);     // bcrypt only uses the first 72 bytes
define('DEFAULT_ROLE', 'Employee');    // the ONLY role self-registration can receive

// Demo mode shows the reset link on screen because there is no mail server.
// MUST be 'false' in production (set APP_DEMO_MODE=false).
define('DEMO_MODE', filter_var(getenv('APP_DEMO_MODE') !== false ? getenv('APP_DEMO_MODE') : 'true', FILTER_VALIDATE_BOOLEAN));

define('LOG_DIR', dirname(__DIR__) . '/logs');

/*
 * ERROR HANDLING (SonarQube: "poor error handling" / information disclosure)
 * VULNERABLE: display_errors=1 prints stack traces, SQL and file paths to attackers.
 * SECURE:     errors go to a log file; users only see a generic message.
 * REASON:     error details help attackers map the application.
 */
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', LOG_DIR . '/php_error.log');
error_reporting(E_ALL);

date_default_timezone_set('UTC');

// ---- RBAC policy (separation of duties and lock-out protection) ----
define('ROLE_ADMIN', 'Administrator');
define('ROLE_AUDITOR', 'Security Auditor');
// The auditor role may ONLY ever hold these read-only permissions.
define('AUDITOR_ALLOWED_PERMISSIONS', ['VIEW_AUDIT_LOGS', 'GENERATE_REPORTS']);
// These can never be removed from the Administrator role (prevents locking everyone out).
define('ADMIN_PROTECTED_PERMISSIONS', ['MANAGE_USERS', 'MANAGE_ROLES', 'MANAGE_PERMISSIONS', 'MANAGE_RESOURCES', 'VIEW_AUDIT_LOGS']);
