<?php
/**
 * SECUREIAM | models/RoleModel.php
 * Roles and the User -> Role assignment table. Prepared statements only.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

class RoleModel
{
    private PDO $db;

    public function __construct()
    {
        $this->db = db();
    }

    public function all(): array
    {
        return $this->db->query(
            'SELECT r.id, r.name, r.description,
                    (SELECT COUNT(*) FROM role_permissions rp WHERE rp.role_id = r.id) AS permission_count,
                    (SELECT COUNT(*) FROM user_roles ur WHERE ur.role_id = r.id)       AS user_count
             FROM roles r ORDER BY r.name'
        )->fetchAll();
    }

    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare('SELECT id, name, description FROM roles WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public function countAll(): int
    {
        return (int) $this->db->query('SELECT COUNT(*) FROM roles')->fetchColumn();
    }

    /** Returns the new id, or null if the name is already used. */
    public function create(string $name, ?string $description): ?int
    {
        try {
            $stmt = $this->db->prepare('INSERT INTO roles (name, description) VALUES (:name, :description)');
            $stmt->execute(['name' => $name, 'description' => ($description === '' ? null : $description)]);
            return (int) $this->db->lastInsertId();
        } catch (PDOException $e) {
            if ($e->getCode() === '23000') {
                return null;
            }
            throw $e;
        }
    }

    /** Returns false when the user already has the role (composite primary key). */
    public function assignToUser(int $userId, int $roleId, int $assignedBy): bool
    {
        try {
            $stmt = $this->db->prepare(
                'INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES (:user, :role, :by)'
            );
            $stmt->execute(['user' => $userId, 'role' => $roleId, 'by' => $assignedBy]);
            return true;
        } catch (PDOException $e) {
            if ($e->getCode() === '23000') {
                return false;
            }
            throw $e;
        }
    }

    public function revokeFromUser(int $userId, int $roleId): bool
    {
        $stmt = $this->db->prepare('DELETE FROM user_roles WHERE user_id = :user AND role_id = :role');
        $stmt->execute(['user' => $userId, 'role' => $roleId]);
        return $stmt->rowCount() > 0;
    }

    public function assignments(): array
    {
        return $this->db->query(
            'SELECT ur.user_id, ur.role_id, u.full_name, u.email, r.name AS role_name,
                    ur.assigned_at, a.full_name AS assigned_by_name
             FROM user_roles ur
             JOIN users u      ON u.id = ur.user_id
             JOIN roles r      ON r.id = ur.role_id
             LEFT JOIN users a ON a.id = ur.assigned_by
             ORDER BY u.full_name, r.name
             LIMIT 300'
        )->fetchAll();
    }

    /**
     * SEPARATION OF DUTIES: the Security Auditor role is exclusive.
     * Without this rule an admin could give an auditor the Administrator role and the
     * "read-only" guarantee would be meaningless. Also used by the approval workflow (Step 7).
     * @return string|null reason the assignment is forbidden, or null when it is allowed
     */
    public static function assignmentConflict(string $newRole, array $currentRoles): ?string
    {
        if (in_array($newRole, $currentRoles, true)) {
            return null;   // already assigned: nothing changes
        }
        if ($newRole === ROLE_AUDITOR && $currentRoles !== []) {
            return 'Separation of duties: remove the user\'s other roles before assigning ' . ROLE_AUDITOR . '.';
        }
        if (in_array(ROLE_AUDITOR, $currentRoles, true)) {
            return 'Separation of duties: a ' . ROLE_AUDITOR . ' cannot hold any other role.';
        }
        return null;
    }
}
