<?php
/**
 * SECUREIAM | controllers/AuthController.php
 * Register, login, logout, forgot/reset password, change password.
 * Controllers validate input, call models, write audit logs, then choose a view.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

class AuthController
{
    // One message for EVERY login failure: unknown email, wrong password, locked, disabled.
    // VULNERABLE: "No such user" / "Wrong password" -> attacker can list valid accounts.
    // SECURE:     identical text -> no user enumeration.
    // BURP DEMO (Login Security): run Intruder on the email field and compare response
    // length and time. They must be identical for existing and non-existing accounts.
    private const LOGIN_ERROR = 'Invalid email or password.';

    private UserModel $users;

    public function __construct()
    {
        $this->users = new UserModel();
    }

    // ------------------------------------------------------------------ LOGIN
    public function login(): void
    {
        if (is_logged_in()) {
            redirect('dashboard');
        }
        $error = null;
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $error = $this->attemptLogin();   // redirects on success
        }
        render('auth/login', [
            'pageTitle' => 'Sign in',
            'error'     => $error,
            'oldEmail'  => normalize_email(post_string('email')),
        ], 'auth');
    }

    /** @return string|null error message, or never returns (redirect) on success */
    private function attemptLogin(): ?string
    {
        $email    = normalize_email(post_string('email'));
        $password = post_string('password');

        if ($email === '' || $password === '' || strlen($password) > 255) {
            return 'Please enter your email and password.';
        }

        $user = $this->users->findByEmail($email);

        if ($user === null) {
            // Burn the same CPU time as a real check so response time does not reveal
            // whether the email exists.
            password_hash($password, PASSWORD_DEFAULT);
            AuditLogModel::log('LOGIN_FAILURE', 'Login attempt for unknown email', null, $email);
            return self::LOGIN_ERROR;
        }

        $userId = (int) $user['id'];

        // A lock that has expired gives the user a fresh set of attempts.
        if ($user['locked_until'] !== null && (int) $user['is_locked'] === 0) {
            $this->users->clearLockout($userId);
        }

        if ((int) $user['is_locked'] === 1) {
            AuditLogModel::log('LOGIN_FAILURE', 'Login attempt while account is locked', $userId, $email);
            return self::LOGIN_ERROR;
        }

        if ($user['status'] !== 'active') {
            AuditLogModel::log('LOGIN_FAILURE', 'Login attempt on disabled account', $userId, $email);
            return self::LOGIN_ERROR;
        }

        // password_verify() reads the salt and cost from the stored hash and compares in
        // constant time. The seed hash '!' can never match.
        // VULNERABLE: if (md5($password) === $user['password']) -- fast, unsalted, crackable.
        // SECURE:     password_verify($password, $hash) with bcrypt from password_hash().
        if (!password_verify($password, $user['password_hash'])) {
            $result = $this->users->registerFailedLogin($userId);
            AuditLogModel::log(
                'LOGIN_FAILURE',
                'Wrong password (failed attempts: ' . $result['attempts'] . ' of ' . MAX_FAILED_ATTEMPTS . ')',
                $userId,
                $email
            );
            if ($result['locked']) {
                AuditLogModel::log(
                    'ACCOUNT_LOCKOUT',
                    'Account locked for ' . LOCKOUT_MINUTES . ' minutes after repeated failures',
                    $userId,
                    $email
                );
            }
            return self::LOGIN_ERROR;
        }

        $this->startUserSession($userId, $user);
        $this->users->recordSuccessfulLogin($userId);
        AuditLogModel::log('LOGIN_SUCCESS', 'User signed in', $userId, $email);

        // Auditors land on the Security Dashboard, everyone else on the Dashboard.
        $target = in_array('GENERATE_REPORTS', $_SESSION['permissions'], true) ? 'auditor' : 'dashboard';
        redirect($target);
        return null;
    }

    private function startUserSession(int $userId, array $user): void
    {
        // Session fixation defence: a new ID is issued at the moment privilege changes.
        // BURP DEMO (Session Management): note the cookie before and after login.
        // Expected: the value changes.
        session_regenerate_id(true);
        unset($_SESSION['csrf_token']);   // fresh CSRF token for the authenticated session

        $_SESSION['user_id']       = $userId;
        $_SESSION['user_name']     = $user['full_name'];
        $_SESSION['user_email']    = $user['email'];
        $_SESSION['roles']         = $this->users->getRoleNames($userId);
        $_SESSION['permissions']   = $this->users->getPermissionNames($userId);
        $_SESSION['last_activity'] = time();
    }

    // --------------------------------------------------------------- REGISTER
    public function register(): void
    {
        if (is_logged_in()) {
            redirect('dashboard');
        }
        $errors = [];

        // MASS ASSIGNMENT DEFENCE: only these four fields are read. A "role" or
        // "role_id" field added in Burp is never looked at; the role is DEFAULT_ROLE.
        // BURP DEMO (Role Escalation): add role=Administrator to the register POST.
        // Expected: the account is created as Employee only.
        $name = trim(post_string('full_name'));
        $email = normalize_email(post_string('email'));
        $dept = trim(post_string('department'));

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $password = post_string('password');

            $errors = array_merge(profile_errors($name, $email, $dept), password_errors($password));
            if ($password !== post_string('password_confirm')) {
                $errors[] = 'Passwords do not match.';
            }

            if ($errors === []) {
                $userId = $this->users->create($name, $email, password_hash($password, PASSWORD_DEFAULT), $dept);
                if ($userId === null) {
                    // Deliberately vague: does not confirm that the email is registered.
                    $errors[] = 'We could not complete your registration. If you already have an account, sign in or reset your password.';
                } else {
                    AuditLogModel::log('USER_CREATE', 'Self-registration (role: ' . DEFAULT_ROLE . ')', $userId, $email);
                    flash_set('success', 'Account created. You can sign in now.');
                    redirect('login');
                }
            }
        }

        render('auth/register', [
            'pageTitle' => 'Create account',
            'errors'    => $errors,
            'old'       => ['full_name' => $name, 'email' => $email, 'department' => $dept],
        ], 'auth');
    }

    // ----------------------------------------------------------------- LOGOUT
    public function logout(): void
    {
        // POST only (CSRF-protected): a GET <img src="...logout"> on another site
        // must not be able to sign the user out.
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            redirect('dashboard');
        }
        AuditLogModel::log('LOGOUT', 'User signed out', current_user_id(), (string) ($_SESSION['user_email'] ?? ''));
        destroy_session();
        flash_set('info', 'You have been signed out.');
        redirect('login');
    }

    // ---------------------------------------------------------- FORGOT / RESET
    public function forgot(): void
    {
        if (get_string('action') === 'reset') {
            $this->resetPassword();
            return;
        }
        $sent = false;
        $demoLink = null;

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $email = normalize_email(post_string('email'));
            if (is_valid_email($email)) {
                $user = $this->users->findByEmail($email);
                if ($user !== null && $user['status'] === 'active') {
                    $token = bin2hex(random_bytes(32));                  // 256-bit random
                    $this->users->setResetToken((int) $user['id'], hash('sha256', $token));
                    $link = url('forgot', ['action' => 'reset', 'token' => $token]);
                    error_log('PASSWORD RESET LINK for ' . $email . ': ' . $link);   // stands in for email
                    AuditLogModel::log('PASSWORD_RESET', 'Password reset requested', (int) $user['id'], $email);
                    $demoLink = DEMO_MODE ? $link : null;
                }
            }
            // Same response whether or not the account exists (no enumeration).
            // NOTE: DEMO_MODE shows the link, which does reveal existence. Turn it off in production.
            $sent = true;
        }

        render('auth/forgot_password', [
            'pageTitle' => 'Forgot password',
            'mode'      => 'request',
            'sent'      => $sent,
            'demoLink'  => $demoLink,
        ], 'auth');
    }

    private function resetPassword(): void
    {
        $isPost = $_SERVER['REQUEST_METHOD'] === 'POST';
        $token  = $isPost ? post_string('token') : get_string('token');
        $user   = preg_match('/^[a-f0-9]{64}$/', $token)
                ? $this->users->findByResetToken(hash('sha256', $token))
                : null;

        if ($user === null) {
            render('auth/forgot_password', ['pageTitle' => 'Reset password', 'mode' => 'invalid'], 'auth');
            return;
        }

        $errors = [];
        if ($isPost) {
            $password = post_string('password');
            $errors = password_errors($password);
            if ($password !== post_string('password_confirm')) {
                $errors[] = 'Passwords do not match.';
            }
            if ($errors === []) {
                $this->users->updatePassword((int) $user['id'], password_hash($password, PASSWORD_DEFAULT));
                AuditLogModel::log('PASSWORD_RESET', 'Password reset completed', (int) $user['id'], $user['email']);
                flash_set('success', 'Password updated. Please sign in.');
                redirect('login');
            }
        }
        render('auth/forgot_password', [
            'pageTitle' => 'Reset password',
            'mode'      => 'reset',
            'token'     => $token,
            'errors'    => $errors,
        ], 'auth');
    }

    // -------------------------------------------------------- CHANGE PASSWORD
    // Router name is "password". Login is enforced centrally in index.php.
    public function password(): void
    {
        $userId = current_user_id();
        $errors = [];

        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $current  = post_string('current_password');
            $password = post_string('password');
            $hash     = $this->users->getPasswordHash($userId);

            if ($hash === null || !password_verify($current, $hash)) {
                $errors[] = 'Your current password is incorrect.';
                AuditLogModel::log('PASSWORD_CHANGE', 'Failed: wrong current password', $userId, $_SESSION['user_email']);
            } else {
                $errors = password_errors($password);
                if ($password === $current) {
                    $errors[] = 'The new password must be different from the current one.';
                }
                if ($password !== post_string('password_confirm')) {
                    $errors[] = 'Passwords do not match.';
                }
            }

            if ($errors === []) {
                $this->users->updatePassword($userId, password_hash($password, PASSWORD_DEFAULT));
                session_regenerate_id(true);
                AuditLogModel::log('PASSWORD_CHANGE', 'Password changed by user', $userId, $_SESSION['user_email']);
                flash_set('success', 'Your password has been changed.');
                redirect('dashboard');
            }
        }
        render('auth/change_password', ['pageTitle' => 'Change password', 'errors' => $errors]);
    }
}
