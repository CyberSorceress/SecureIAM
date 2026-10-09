<?php
/**
 * SECUREIAM | controllers/PermissionController.php
 * Create permissions, grant / revoke them on roles. Route permission: MANAGE_PERMISSIONS.
 *
 * BURP DEMO (Auditor stays read-only): as Administrator, tick PUSH_CODE for the
 * Security Auditor role (or add its id to permission_ids[] in Repeater).
 * Expected: refused, ACCESS_DENIED logged. The UI also disables the box, but the SERVER decides.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

class PermissionController
{
    private PermissionModel $permissions;
    private RoleModel $roles;
    private ResourceModel $resources;

    public function __construct()
    {
        $this->permissions = new PermissionModel();
        $this->roles       = new RoleModel();
        $this->resources   = new ResourceModel();
    }

    public function index(): void
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $this->handlePost(get_string('action'));
            return;
        }

        $roles    = $this->roles->all();
        $selected = $roles[0] ?? null;
        foreach ($roles as $role) {
            if ((int) $role['id'] === get_int('role_id')) {
                $selected = $role;
            }
        }
        render('permissions/index', [
            'pageTitle'    => 'Permission Management',
            'permissions'  => $this->permissions->all(),
            'resources'    => $this->resources->all(),
            'roles'        => $roles,
            'selectedRole' => $selected,
            'grantedIds'   => $selected === null ? [] : $this->permissions->idsForRole((int) $selected['id']),
        ]);
    }

    private function handlePost(string $action): void
    {
        match ($action) {
            'create' => $this->create(),
            'sync'   => $this->syncRolePermissions(),
            default  => render_error(404),
        };
    }

    private function create(): void
    {
        $name     = trim(post_string('name'));
        $desc     = trim(post_string('description'));
        $resource = $this->resources->findById(post_int('resource_id'));

        if (!is_valid_permission_name($name)) {
            $this->fail('Permission names use CAPITAL_LETTERS_AND_UNDERSCORES (3-80 characters).');
        }
        if (!is_valid_description($desc) || $resource === null) {
            $this->fail('Enter a valid description and choose an existing resource.');
        }
        if ($this->permissions->create($name, $desc, (int) $resource['id']) === null) {
            $this->fail('A permission with that name already exists.');
        }
        AuditLogModel::log('PERMISSION_CREATE', 'Created permission ' . $name . ' on ' . $resource['name'], current_user_id(), $_SESSION['user_email']);
        flash_set('success', 'Permission created.');
        redirect('permissions');
    }

    /** Saves the checkbox panel: grants what was ticked, revokes what was unticked. */
    private function syncRolePermissions(): void
    {
        $role = $this->roles->findById(post_int('role_id'));
        if ($role === null) {
            $this->fail('Role not found.');
        }
        $roleId = (int) $role['id'];

        $byId = [];
        foreach ($this->permissions->all() as $permission) {
            $byId[(int) $permission['id']] = $permission;
        }
        $submitted = array_values(array_filter(post_int_array('permission_ids'), static fn (int $id): bool => isset($byId[$id])));
        $current   = $this->permissions->idsForRole($roleId);
        $actor     = current_user_id();

        $granted = 0;
        $revoked = 0;
        $denied  = [];

        foreach (array_diff($submitted, $current) as $permissionId) {
            $name = $byId[$permissionId]['name'];
            if ($role['name'] === ROLE_AUDITOR && !in_array($name, AUDITOR_ALLOWED_PERMISSIONS, true)) {
                $denied[] = $name . ' (the auditor role is read-only)';
                AuditLogModel::log('ACCESS_DENIED', 'Blocked grant of ' . $name . ' to read-only role ' . $role['name'], $actor, $_SESSION['user_email']);
                continue;
            }
            if ($this->permissions->addToRole($roleId, $permissionId, $actor)) {
                $granted++;
                AuditLogModel::log('PERMISSION_ASSIGN', 'Granted ' . $name . ' to role ' . $role['name'], $actor, $_SESSION['user_email']);
            }
        }

        foreach (array_diff($current, $submitted) as $permissionId) {
            $name = $byId[$permissionId]['name'] ?? null;
            if ($name === null) {
                continue;
            }
            if ($role['name'] === ROLE_ADMIN && in_array($name, ADMIN_PROTECTED_PERMISSIONS, true)) {
                $denied[] = $name . ' (protected, would lock administrators out)';
                AuditLogModel::log('ACCESS_DENIED', 'Blocked revoke of protected ' . $name . ' from ' . $role['name'], $actor, $_SESSION['user_email']);
                continue;
            }
            if ($this->permissions->removeFromRole($roleId, $permissionId)) {
                $revoked++;
                AuditLogModel::log('PERMISSION_REVOKE', 'Revoked ' . $name . ' from role ' . $role['name'], $actor, $_SESSION['user_email']);
            }
        }

        flash_set('success', $role['name'] . ': ' . $granted . ' granted, ' . $revoked . ' revoked.');
        if ($denied !== []) {
            flash_set('warning', 'Not changed: ' . implode('; ', $denied) . '.');
        }
        redirect('permissions', ['role_id' => $roleId]);
    }

    private function fail(string $message): void
    {
        flash_set('danger', $message);
        redirect('permissions');
    }
}
