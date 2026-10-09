<?php
/**
 * SECUREIAM | includes/csrf.php
 * CSRF protection (synchroniser-token pattern).
 *
 * HOW IT WORKS: the server stores a random token in the session and embeds the same
 * token in every form. A malicious site can make the victim's browser send a request
 * (with cookies) but cannot read the token, so it cannot forge a valid form.
 *
 * VULNERABLE: process any POST that carries a valid session cookie.
 * SECURE:     also require a matching, unpredictable token (checked in index.php).
 * REASON:     cookies are sent automatically by the browser; tokens are not.
 *
 * BURP DEMO (CSRF): in Repeater remove or alter the csrf_token field of any POST.
 * Expected: HTTP 403 and an ACCESS_DENIED audit entry.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . e(csrf_token()) . '">';
}

function csrf_is_valid(): bool
{
    $sent = $_POST['csrf_token'] ?? '';
    // hash_equals = constant-time comparison (prevents timing attacks)
    return is_string($sent) && $sent !== '' && hash_equals(csrf_token(), $sent);
}
