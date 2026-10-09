<?php
/**
 * SECUREIAM | index.php  (front controller)
 * EVERY request enters here: index.php?page=<page>&action=<action>
 *
 * Why one entry point? There is exactly one place that enforces the session,
 * CSRF and access rules, so no page can be added without them.
 */
declare(strict_types=1);

define('SECUREIAM', true);

define('ROOT_PATH', __DIR__ . DIRECTORY_SEPARATOR);

require ROOT_PATH . 'config.php';
require ROOT_PATH . 'database.php';
require ROOT_PATH . 'session.php';
require ROOT_PATH . 'csrf.php';
require ROOT_PATH . 'validator.php';
require ROOT_PATH . 'auth_guard.php';

// Class names come only from the route table below, never from user input.
spl_autoload_register(static function (string $class): void {
    foreach (['models', 'controllers'] as $dir) {
        $file = ROOT_PATH . '/' . $dir . '/' . $class . '.php';
        if (preg_match('/^[A-Za-z]+$/', $class) && is_file($file)) {
            require $file;
            return;
        }
    }
});

/** Renders a view inside the header/footer layout. $layout: 'app' (sidebar) or 'auth'. */
function render(string $view, array $data = [], string $layout = 'app'): void
{
    if (!preg_match('#^[a-z_]+/[a-z_]+$#', $view) || !is_file(ROOT_PATH . '/views/' . $view . '.php')) {
        throw new InvalidArgumentException('Unknown view');
    }
    $pageTitle = (string) ($data['pageTitle'] ?? APP_NAME);
    extract($data, EXTR_SKIP);   // SKIP: view data can never overwrite $view, $layout, etc.
    require ROOT_PATH . '/includes/header.php';
    require ROOT_PATH . '/views/' . $view . '.php';
    require ROOT_PATH . '/includes/footer.php';
}

function render_error(int $code): void
{
    $titles = [403 => 'Access denied', 404 => 'Page not found', 405 => 'Method not allowed', 500 => 'Server error'];
    http_response_code($code);
    render('errors/error', [
        'pageTitle' => $titles[$code] ?? 'Error',
        'code'      => $code,
        'message'   => $titles[$code] ?? 'Error',
    ], is_logged_in() ? 'app' : 'auth');
}

// ---------- Security headers (sent on every response) ----------
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');                 // clickjacking defence
header('Referrer-Policy: no-referrer');          // reset tokens in URLs are not leaked
header('Cache-Control: no-store');               // sensitive pages are never cached
header("Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
     . "style-src 'self' https://cdn.jsdelivr.net; font-src 'self' https://cdn.jsdelivr.net; "
     . "img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'self'");

start_secure_session();

/*
 * ROUTE TABLE (whitelist). Format: page => [Controller, method, access, required permission]
 *   access 'public' = anyone, 'auth' = must be logged in.
 *   4th value = permission checked by require_permission() BEFORE the controller runs.
 * Unknown pages return 404, so ?page=../../etc/passwd goes nowhere.
 * The sidebar is generated from this same table, so menu and enforcement cannot drift apart.
 */
$routes = [
    'login'       => ['AuthController',       'login',    'public'],
    'register'    => ['AuthController',       'register', 'public'],
    'forgot'      => ['AuthController',       'forgot',   'public'],
    'logout'      => ['AuthController',       'logout',   'auth'],
    'password'    => ['AuthController',       'password', 'auth'],
    'dashboard'   => ['DashboardController',  'index',    'auth'],
    'users'       => ['UserController',       'index',    'auth', 'MANAGE_USERS'],
    'roles'       => ['RoleController',       'index',    'auth', 'MANAGE_ROLES'],
    'permissions' => ['PermissionController', 'index',    'auth', 'MANAGE_PERMISSIONS'],
    'resources'   => ['ResourceController',   'index',    'auth', 'MANAGE_RESOURCES'],
];

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if (!in_array($method, ['GET', 'POST'], true)) {
    render_error(405);
    exit;
}

// BURP DEMO (Access Control): change ?page= to a page you should not see.
$page = get_string('page');
if ($page === '') {
    redirect(is_logged_in() ? 'dashboard' : 'login');
}
if (!isset($routes[$page])) {
    render_error(404);
    exit;
}
[$controllerName, $methodName, $access, $permission] = array_pad($routes[$page], 4, null);

try {
    // CSRF check for EVERY state-changing request, before any controller runs.
    if ($method === 'POST' && !csrf_is_valid()) {
        AuditLogModel::log(
            'ACCESS_DENIED',
            'CSRF token missing or invalid on page "' . $page . '"',
            is_logged_in() ? current_user_id() : null,
            $_SESSION['user_email'] ?? null
        );
        render_error(403);
        exit;
    }

    if ($access === 'auth') {
        require_login();
    }
    if ($permission !== null) {
        require_permission($permission);   // 403 + audit entry when missing
    }

    (new $controllerName())->$methodName();
} catch (Throwable $e) {
    // Full detail goes to the log, the user sees nothing sensitive.
    error_log(sprintf('Unhandled %s: %s in %s:%d', get_class($e), $e->getMessage(), $e->getFile(), $e->getLine()));
    render_error(500);
}
