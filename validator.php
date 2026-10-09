<?php
/**
 * SECUREIAM | includes/validator.php
 * Input validation and output escaping helpers.
 *
 * RULE: validate on the way IN (here), escape on the way OUT (e()).
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

/**
 * Output escaping (prevents stored/reflected XSS).
 * VULNERABLE: echo $_POST['name'];
 * SECURE:     echo e($_POST['name']);
 */
function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/**
 * Reads a POST field as a string. If an attacker sends name[]=x (parameter
 * pollution, easy to try in Burp) the result is '' instead of a PHP array.
 */
function post_string(string $key): string
{
    $value = $_POST[$key] ?? '';
    return is_string($value) ? $value : '';
}

function get_string(string $key): string
{
    $value = $_GET[$key] ?? '';
    return is_string($value) ? $value : '';
}

function normalize_email(string $email): string
{
    return mb_strtolower(trim($email));
}

function is_valid_email(string $email): bool
{
    return strlen($email) <= 150 && filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function is_valid_full_name(string $name): bool
{
    return (bool) preg_match('/^[\p{L}][\p{L}\p{M}\s.\'-]{1,99}$/u', $name);
}

function is_valid_department(string $dept): bool
{
    return (bool) preg_match('/^[\p{L}\p{N}\s&.,\'-]{0,100}$/u', $dept);
}

/** Returns a list of problems; an empty list means the password is acceptable. */
function password_errors(string $password): array
{
    $errors = [];
    if (strlen($password) < MIN_PASSWORD_LENGTH) {
        $errors[] = 'Password must be at least ' . MIN_PASSWORD_LENGTH . ' characters.';
    }
    if (strlen($password) > MAX_PASSWORD_LENGTH) {
        $errors[] = 'Password must be at most ' . MAX_PASSWORD_LENGTH . ' characters.';
    }
    if (!preg_match('/\p{Ll}/u', $password) || !preg_match('/\p{Lu}/u', $password)) {
        $errors[] = 'Password must contain upper and lower case letters.';
    }
    if (!preg_match('/\d/', $password)) {
        $errors[] = 'Password must contain a number.';
    }
    if (!preg_match('/[^\p{L}\d]/u', $password)) {
        $errors[] = 'Password must contain a symbol.';
    }
    return $errors;
}

/** Client IP for the audit log. REMOTE_ADDR only: X-Forwarded-For is attacker-controlled. */
function client_ip(): ?string
{
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    return filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : null;
}

function get_int(string $key): int
{
    $value = get_string($key);
    return ctype_digit($value) && strlen($value) <= 10 ? (int) $value : 0;
}

/** Numeric ID from POST. Anything that is not plain digits becomes 0 (= "not found"). */
function post_int(string $key): int
{
    $value = post_string($key);
    return ctype_digit($value) && strlen($value) <= 10 ? (int) $value : 0;
}

/** List of numeric IDs from POST (e.g. checkboxes). Non-numeric entries are dropped. */
function post_int_array(string $key): array
{
    $raw = $_POST[$key] ?? [];
    if (!is_array($raw)) {
        return [];
    }
    $ids = [];
    foreach ($raw as $value) {
        if (is_string($value) && ctype_digit($value) && strlen($value) <= 10) {
            $ids[] = (int) $value;
        }
    }
    return array_values(array_unique($ids));
}

/** Role and resource names. */
function is_valid_label(string $value): bool
{
    return (bool) preg_match('/^[\p{L}\p{N}][\p{L}\p{N} _&.\'-]{1,79}$/u', $value);
}

/** Permission names must look like READ_EMPLOYEE_DATA. */
function is_valid_permission_name(string $value): bool
{
    return (bool) preg_match('/^[A-Z][A-Z0-9_]{2,79}$/', $value);
}

function is_valid_description(string $value): bool
{
    return (bool) preg_match('/^[^\x00-\x1F\x7F]{0,255}$/u', $value);
}

/** Shared by self-registration and admin user creation/editing (no duplicated rules). */
function profile_errors(string $name, string $email, string $department): array
{
    $errors = [];
    if (!is_valid_full_name($name)) {
        $errors[] = 'Enter a valid full name (letters, spaces, . \' - only).';
    }
    if (!is_valid_email($email)) {
        $errors[] = 'Enter a valid email address.';
    }
    if (!is_valid_department($department)) {
        $errors[] = 'Department contains invalid characters.';
    }
    return $errors;
}
