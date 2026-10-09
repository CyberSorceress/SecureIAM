<?php
/**
 * SECUREIAM | controllers/UserController.php
 * Create / edit / disable users. Route permission: MANAGE_USERS (enforced in index.php).
 *
 * BURP DEMO (Authorization): as an Employee, POST ?page=users&action=create.
 * Expected: HTTP 403 before this class is even created.
 * BURP DEMO (Mass assignment): add status=active, role_id=1 or is_system=1 to any form here.
 * Expected: ignored; only the fields read below are used.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

class UserController
{
    private UserModel $users;

    public function __construct()
    {
        $this->users = new UserModel();
    }

    public function index(): void
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $this->handlePost(get_string('action'));
            return;
        }
        render('users/index', [
            'pageTitle' => 'User Management',
            'users'     => $this->users->listWithRoles(),
        ]);
    }

    // Whitelist of actions. Anything else is a 404.
    private function handlePost(string $action): void
    {
        match ($action) {
            'create'  => $this->create(),
            'edit'    => $this->edit(),
            'disable' => $this->changeStatus('disabled'),
            'enable'  => $this->changeStatus('active'),
            default   => render_error(404),
        };
    }

    private function create(): void
    {
        $name     = trim(post_string('full_name'));
        $email    = normalize_email(post_string('email'));
        $dept     = trim(post_string('department'));
        $password = post_string('password');

        $errors = array_merge(profile_errors($name, $email, $dept), password_errors($password));
        if ($errors !== []) {
            $this->fail(implode(' ', $errors));
        }

        // create() always assigns DEFAULT_ROLE; roles are changed on the Roles page (MANAGE_ROLES).
        $id = $this->users->create($name, $email, password_hash($password, PASSWORD_DEFAULT), $dept);
        if ($id === null) {
            $this->fail('A user with that email already exists.');
        }
        AuditLogModel::log('USER_CREATE', 'Created user ' . $email . ' (role: ' . DEFAULT_ROLE . ')', current_user_id(), $_SESSION['user_email']);
        flash_set('success', 'User created. Assign extra roles on the Roles page.');
        redirect('users');
    }

    private function edit(): void
    {
        $user = $this->users->findById(post_int('user_id'));
        if ($user === null) {
            $this->fail('User not found.');
        }
        $name  = trim(post_string('full_name'));
        $email = normalize_email(post_string('email'));
        $dept  = trim(post_string('department'));

        $errors = profile_errors($name, $email, $dept);
        if ($errors !== []) {
            $this->fail(implode(' ', $errors));
        }
        if (!$this->users->updateProfile((int) $user['id'], $name, $email, $dept)) {
            $this->fail('Another user already uses that email.');
        }

        $changed = [];
        foreach (['full_name' => $name, 'email' => $email, 'department' => $dept] as $field => $new) {
            if ((string) ($user[$field] ?? '') !== $new) {
                $changed[] = $field;
            }
        }
        AuditLogModel::log(
            'USER_EDIT',
            'Edited user ' . $user['email'] . ' (changed: ' . ($changed === [] ? 'nothing' : implode(', ', $changed)) . ')',
            current_user_id(),
            $_SESSION['user_email']
        );
        flash_set('success', 'User updated.');
        redirect('users');
    }

    private function changeStatus(string $status): void
    {
        $user = $this->users->findById(post_int('user_id'));
        if ($user === null) {
            $this->fail('User not found.');
        }
        $userId = (int) $user['id'];

        // An administrator must not be able to lock themselves out.
        if ($status === 'disabled' && $userId === current_user_id()) {
            $this->fail('You cannot disable your own account.');
        }
        if ($user['status'] === $status) {
            flash_set('info', 'No change: the user already has that status.');
            redirect('users');
        }

        $this->users->setStatus($userId, $status);
        if ($status === 'active') {
            $this->users->clearLockout($userId);   // a re-enabled user starts clean
            AuditLogModel::log('USER_EDIT', 'Re-enabled user ' . $user['email'], current_user_id(), $_SESSION['user_email']);
            flash_set('success', 'User re-enabled.');
        } else {
            AuditLogModel::log('USER_DISABLE', 'Disabled user ' . $user['email'], current_user_id(), $_SESSION['user_email']);
            flash_set('success', 'User disabled. Their sessions stop working immediately.');
        }
        redirect('users');
    }

    private function fail(string $message): void
    {
        flash_set('danger', $message);
        redirect('users');
    }
}
