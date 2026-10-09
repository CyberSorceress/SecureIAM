<?php
/**
 * SECUREIAM | includes/auth_guard.php
 * The security core: authentication + RBAC (User -> Role -> Permission).
 * Called from ONE place (index.php) for every protected page, so no controller can forget it.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

function require_login(): void
{
    if (!is_logged_in()) {
        flash_set('warning', 'Please sign in to continue.');
        redirect('login');
    }

    // Re-check the database on EVERY request, so disabling a user or revoking a role
    // takes effect immediately instead of waiting for the session to expire.
    // BURP DEMO (Access Control): disable a user or revoke their role, then replay that
    // user's old session cookie. Expected: login redirect (disabled) or 403 (revoked).
    $users  = new UserModel();
    $userId = current_user_id();
    if (!$users->isActive($userId)) {
        destroy_session();
        flash_set('danger', 'Your account is no longer active.');
        redirect('login');
    }
    $_SESSION['roles']       = $users->getRoleNames($userId);
    $_SESSION['permissions'] = $users->getPermissionNames($userId);
}

/** True when ANY of the user's roles grants the permission (union of all roles). */
function has_permission(string $permission): bool
{
    return in_array($permission, $_SESSION['permissions'] ?? [], true);
}

/**
 * Authorization gate. Checks PERMISSIONS, not role names, so adding a new role needs no code change.
 * Failures are written to the audit log, so Burp attacks leave visible evidence.
 *
 * VULNERABLE: if ($_SESSION['role'] == 'admin') ...  or  trusting a hidden field / cookie / URL parameter
 * SECURE:     permission looked up server-side from the database via the user's roles
 * REASON:     anything the browser sends can be edited in Burp; the database cannot.
 *
 * BURP DEMO (Authorization / Role Escalation): log in as an Employee and request
 * ?page=users or POST ?page=roles&action=assign. Expected: HTTP 403 + ACCESS_DENIED row.
 */
function require_permission(string $permission): void
{
    if (has_permission($permission)) {
        return;
    }
    AuditLogModel::log(
        'ACCESS_DENIED',
        'Missing permission ' . $permission . ' for page "' . mb_substr(get_string('page'), 0, 30)
            . '" (action: ' . mb_substr(get_string('action'), 0, 30) . ')',
        current_user_id(),
        $_SESSION['user_email'] ?? null
    );
    render_error(403);
    exit;
}
