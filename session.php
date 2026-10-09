<?php
/**
 * SECUREIAM | includes/session.php
 * Secure session handling, idle timeout, redirects and flash messages.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

function start_secure_session(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';

    ini_set('session.use_strict_mode', '1');   // server rejects session IDs it did not issue
    ini_set('session.use_only_cookies', '1');  // never accept IDs from the URL
    ini_set('session.use_trans_sid', '0');

    session_name('SECUREIAM_SID');
    session_set_cookie_params([
        'lifetime' => 0,          // browser-session cookie
        'path'     => '/',
        'secure'   => $https,     // HTTPS only when the site is served over HTTPS
        'httponly' => true,       // JavaScript cannot read the cookie (limits XSS damage)
        'samesite' => 'Strict',   // cookie not sent on cross-site requests (limits CSRF)
    ]);
    session_start();

    // BURP DEMO (Session Management): capture a session cookie, wait 15+ minutes,
    // replay it in Repeater. Expected: redirected to login with "session expired".
    if (isset($_SESSION['user_id'], $_SESSION['last_activity'])
        && (time() - (int) $_SESSION['last_activity']) > SESSION_TIMEOUT) {
        destroy_session();
        flash_set('warning', 'Your session expired due to inactivity. Please sign in again.');
        return;
    }
    if (isset($_SESSION['user_id'])) {
        $_SESSION['last_activity'] = time();
    }
}

/** Fully destroys the session, then starts a clean anonymous one (needed for flash messages). */
function destroy_session(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $p = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires'  => time() - 3600,
            'path'     => $p['path'],
            'domain'   => $p['domain'],
            'secure'   => $p['secure'],
            'httponly' => $p['httponly'],
            'samesite' => $p['samesite'],
        ]);
    }
    session_destroy();
    session_start();
    session_regenerate_id(true);
}

function is_logged_in(): bool
{
    return !empty($_SESSION['user_id']);
}

function current_user_id(): int
{
    return (int) ($_SESSION['user_id'] ?? 0);
}

/**
 * Builds an internal URL. Redirect targets are always built from a page name
 * chosen by our own code, never from user input (prevents open redirects).
 */
function url(string $page, array $params = []): string
{
    return 'index.php?' . http_build_query(array_merge(['page' => $page], $params));
}

function redirect(string $page, array $params = []): void
{
    header('Location: ' . url($page, $params));
    exit;
}

// ---------- Flash messages (shown once, then removed) ----------
function flash_set(string $type, string $message): void
{
    $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
}

function render_flash(): string
{
    $allowed = ['success', 'danger', 'warning', 'info'];
    $html = '';
    foreach ($_SESSION['flash'] ?? [] as $flash) {
        $type  = in_array($flash['type'], $allowed, true) ? $flash['type'] : 'info';
        $html .= '<div class="alert alert-' . $type . ' alert-dismissible fade show" role="alert">'
              . e($flash['message'])
              . '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>';
    }
    unset($_SESSION['flash']);
    return $html;
}
