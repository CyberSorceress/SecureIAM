<?php
/**
 * SECUREIAM | controllers/RoleController.php
 * Create roles, assign / revoke roles. Route permission: MANAGE_ROLES.
 *
 * BURP DEMO (Role Escalation): as an Employee or the Security Auditor, POST
 * ?page=roles&action=assign with user_id/role_id. Expected: 403 + ACCESS_DENIED row.
 * BURP DEMO (IDOR / tampering): as Administrator, give the Auditor a second role.
 * Expected: refused by the separation-of-duties rule and logged.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

class RoleController
{
    private RoleModel $roles;
    private UserModel $users;

    public function __construct()
    {
        $this->roles = new RoleModel();
        $this->users = new UserModel();
    }

    public function index(): void
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $this->handlePost(get_string('action'));
            return;
        }
        render('roles/index', [
            'pageTitle'   => 'Role Management',
            'roles'       => $this->roles->all(),
            'users'       => $this->users->listActive(),
            'assignments' => $this->roles->assignments(),
        ]);
    }

    private function handlePost(string $action): void
    {
        match ($action) {
            'create' => $this->create(),
            'assign' => $this->assign(),
            'revoke' => $this->revoke(),
            default  => render_error(404),
        };
    }

    private function create(): void
    {
        $name = trim(post_string('name'));
        $desc = trim(post_string('description'));
        if (!is_valid_label($name) || !is_valid_description($desc)) {
            $this->fail('Enter a valid role name (2-80 characters) and description.');
        }
        if ($this->roles->create($name, $desc) === null) {
            $this->fail('A role with that name already exists.');
        }
        // New roles start with NO permissions (least privilege).
        AuditLogModel::log('ROLE_CREATE', 'Created role ' . $name, current_user_id(), $_SESSION['user_email']);
        flash_set('success', 'Role created. Grant it permissions on the Permissions page.');
        redirect('roles');
    }

    private function assign(): void
    {
        $user = $this->users->findById(post_int('user_id'));
        $role = $this->roles->findById(post_int('role_id'));
        if ($user === null || $role === null || $user['status'] !== 'active') {
            $this->fail('Choose an active user and an existing role.');
        }

        $conflict = RoleModel::assignmentConflict($role['name'], $this->users->getRoleNames((int) $user['id']));
        if ($conflict !== null) {
            AuditLogModel::log('ACCESS_DENIED', 'Blocked role assignment ' . $role['name'] . ' to ' . $user['email'] . ': ' . $conflict, current_user_id(), $_SESSION['user_email']);
            $this->fail($conflict);
        }

        if (!$this->roles->assignToUser((int) $user['id'], (int) $role['id'], current_user_id())) {
            flash_set('info', 'That user already has this role.');
            redirect('roles');
        }
        AuditLogModel::log('ROLE_ASSIGN', 'Assigned role ' . $role['name'] . ' to ' . $user['email'], current_user_id(), $_SESSION['user_email']);
        flash_set('success', 'Role assigned.');
        redirect('roles');
    }

    private function revoke(): void
    {
        $user = $this->users->findById(post_int('user_id'));
        $role = $this->roles->findById(post_int('role_id'));
        if ($user === null || $role === null) {
            $this->fail('Assignment not found.');
        }
        // Prevent an administrator from removing their own admin access by mistake.
        if ((int) $user['id'] === current_user_id() && $role['name'] === ROLE_ADMIN) {
            $this->fail('You cannot revoke your own Administrator role.');
        }
        if (!$this->roles->revokeFromUser((int) $user['id'], (int) $role['id'])) {
            $this->fail('Assignment not found.');
        }
        AuditLogModel::log('ROLE_REVOKE', 'Revoked role ' . $role['name'] . ' from ' . $user['email'], current_user_id(), $_SESSION['user_email']);
        flash_set('success', 'Role revoked. It takes effect on the user\'s next request.');
        redirect('roles');
    }

    private function fail(string $message): void
    {
        flash_set('danger', $message);
        redirect('roles');
    }
}
