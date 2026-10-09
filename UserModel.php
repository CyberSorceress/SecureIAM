<?php
/**
 * SECUREIAM | models/UserModel.php
 * All user-related SQL lives here, and ALL of it uses prepared statements.
 *
 * SonarQube: SQL injection
 * VULNERABLE: $db->query("SELECT * FROM users WHERE email = '$email'");
 *             (input  ' OR '1'='1' -- logs an attacker in without a password)
 * SECURE:     $stmt = $db->prepare('SELECT ... WHERE email = :email');
 *             $stmt->execute(['email' => $email]);
 * REASON:     the SQL text is compiled first and the value is sent separately,
 *             so input can never be interpreted as SQL.
 *
 * BURP DEMO (Login Security): send ' OR '1'='1 as the email in Intruder/Repeater.
 * Expected: normal "Invalid email or password" response, no error text.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

class UserModel
{
    private PDO $db;

    public function __construct()
    {
        $this->db = db();
    }

    public function findByEmail(string $email): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT id, full_name, email, password_hash, status, failed_attempts, locked_until,
                    (locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked
             FROM users WHERE email = :email LIMIT 1'
        );
        $stmt->execute(['email' => $email]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public function isActive(int $id): bool
    {
        $stmt = $this->db->prepare("SELECT 1 FROM users WHERE id = :id AND status = 'active'");
        $stmt->execute(['id' => $id]);
        return $stmt->fetchColumn() !== false;
    }

    /**
     * Creates a user and gives them the default Employee role in ONE transaction.
     * Returns the new id, or null when the email already exists (UNIQUE constraint).
     * Relying on the constraint is race-free, unlike "SELECT first, then INSERT".
     */
    public function create(string $name, string $email, string $passwordHash, ?string $department): ?int
    {
        try {
            $this->db->beginTransaction();

            $stmt = $this->db->prepare(
                'INSERT INTO users (full_name, email, password_hash, department)
                 VALUES (:name, :email, :hash, :dept)'
            );
            $stmt->execute([
                'name'  => $name,
                'email' => $email,
                'hash'  => $passwordHash,
                'dept'  => ($department === '' ? null : $department),
            ]);
            $userId = (int) $this->db->lastInsertId();

            // Role comes from a server-side constant, never from the request.
            $role = $this->db->prepare(
                'INSERT INTO user_roles (user_id, role_id)
                 SELECT :uid, id FROM roles WHERE name = :role'
            );
            $role->execute(['uid' => $userId, 'role' => DEFAULT_ROLE]);
            if ($role->rowCount() !== 1) {
                throw new RuntimeException('Default role is missing. Was seed.sql imported?');
            }

            $this->db->commit();
            return $userId;
        } catch (PDOException $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            if ($e->getCode() === '23000') {   // duplicate email
                return null;
            }
            throw $e;
        } catch (RuntimeException $e) {
            if ($this->db->inTransaction()) {
                $this->db->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Counts a failed login and locks the account when the limit is reached.
     * One atomic UPDATE avoids race conditions between parallel guesses.
     * NOTE: locked_until is assigned BEFORE failed_attempts on purpose; MySQL applies
     * SET clauses left to right, so the IF() still sees the old counter.
     */
    public function registerFailedLogin(int $id): array
    {
        $stmt = $this->db->prepare(
            'UPDATE users
             SET locked_until    = IF(failed_attempts + 1 >= :max, DATE_ADD(NOW(), INTERVAL :mins MINUTE), locked_until),
                 failed_attempts = failed_attempts + 1
             WHERE id = :id'
        );
        $stmt->execute(['max' => MAX_FAILED_ATTEMPTS, 'mins' => LOCKOUT_MINUTES, 'id' => $id]);

        $check = $this->db->prepare(
            'SELECT failed_attempts, (locked_until IS NOT NULL AND locked_until > NOW()) AS is_locked
             FROM users WHERE id = :id'
        );
        $check->execute(['id' => $id]);
        $row = $check->fetch();
        return ['attempts' => (int) $row['failed_attempts'], 'locked' => (int) $row['is_locked'] === 1];
    }

    /** Called when a lock has expired, so the user gets a fresh set of attempts. */
    public function clearLockout(int $id): void
    {
        $stmt = $this->db->prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = :id');
        $stmt->execute(['id' => $id]);
    }

    public function recordSuccessfulLogin(int $id): void
    {
        $stmt = $this->db->prepare(
            'UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = NOW() WHERE id = :id'
        );
        $stmt->execute(['id' => $id]);
    }

    /** Sets a new password and invalidates any outstanding reset token and lockout. */
    public function updatePassword(int $id, string $passwordHash): void
    {
        $stmt = $this->db->prepare(
            'UPDATE users
             SET password_hash = :hash, reset_token_hash = NULL, reset_expires_at = NULL,
                 failed_attempts = 0, locked_until = NULL
             WHERE id = :id'
        );
        $stmt->execute(['hash' => $passwordHash, 'id' => $id]);
    }

    public function getPasswordHash(int $id): ?string
    {
        $stmt = $this->db->prepare('SELECT password_hash FROM users WHERE id = :id');
        $stmt->execute(['id' => $id]);
        $hash = $stmt->fetchColumn();
        return $hash === false ? null : (string) $hash;
    }

    /** Only the SHA-256 of the token is stored; the real token exists only in the link. */
    public function setResetToken(int $id, string $tokenHash): void
    {
        $stmt = $this->db->prepare(
            'UPDATE users
             SET reset_token_hash = :hash, reset_expires_at = DATE_ADD(NOW(), INTERVAL :mins MINUTE)
             WHERE id = :id'
        );
        $stmt->execute(['hash' => $tokenHash, 'mins' => RESET_TOKEN_MINUTES, 'id' => $id]);
    }

    public function findByResetToken(string $tokenHash): ?array
    {
        $stmt = $this->db->prepare(
            "SELECT id, email FROM users
             WHERE reset_token_hash = :hash AND reset_expires_at > NOW() AND status = 'active'
             LIMIT 1"
        );
        $stmt->execute(['hash' => $tokenHash]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    public function getRoleNames(int $userId): array
    {
        $stmt = $this->db->prepare(
            'SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id
             WHERE ur.user_id = :id ORDER BY r.name'
        );
        $stmt->execute(['id' => $userId]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    /** User -> Role -> Permission, flattened. Step 6 builds has_permission() on this. */
    public function getPermissionNames(int $userId): array
    {
        $stmt = $this->db->prepare(
            'SELECT DISTINCT p.name
             FROM user_roles ur
             JOIN role_permissions rp ON rp.role_id = ur.role_id
             JOIN permissions p       ON p.id = rp.permission_id
             WHERE ur.user_id = :id ORDER BY p.name'
        );
        $stmt->execute(['id' => $userId]);
        return $stmt->fetchAll(PDO::FETCH_COLUMN);
    }

    // ---------------------------------------------------------------
    // Administration queries (used by UserController / dashboard)
    // ---------------------------------------------------------------
    public function findById(int $id): ?array
    {
        $stmt = $this->db->prepare(
            'SELECT id, full_name, email, department, status FROM users WHERE id = :id LIMIT 1'
        );
        $stmt->execute(['id' => $id]);
        $row = $stmt->fetch();
        return $row === false ? null : $row;
    }

    /** All users with their role names in one query (no N+1 queries). */
    public function listWithRoles(): array
    {
        return $this->db->query(
            "SELECT u.id, u.full_name, u.email, u.department, u.status, u.last_login_at,
                    GROUP_CONCAT(r.name ORDER BY r.name SEPARATOR ', ') AS roles
             FROM users u
             LEFT JOIN user_roles ur ON ur.user_id = u.id
             LEFT JOIN roles r       ON r.id = ur.role_id
             GROUP BY u.id
             ORDER BY u.full_name"
        )->fetchAll();
    }

    public function listActive(): array
    {
        return $this->db->query(
            "SELECT id, full_name, email FROM users WHERE status = 'active' ORDER BY full_name"
        )->fetchAll();
    }

    /** Returns false when the new email belongs to another account (UNIQUE constraint). */
    public function updateProfile(int $id, string $name, string $email, ?string $department): bool
    {
        try {
            $stmt = $this->db->prepare(
                'UPDATE users SET full_name = :name, email = :email, department = :dept WHERE id = :id'
            );
            $stmt->execute([
                'name'  => $name,
                'email' => $email,
                'dept'  => ($department === '' ? null : $department),
                'id'    => $id,
            ]);
            return true;
        } catch (PDOException $e) {
            if ($e->getCode() === '23000') {
                return false;
            }
            throw $e;
        }
    }

    public function setStatus(int $id, string $status): void
    {
        if (!in_array($status, ['active', 'disabled'], true)) {
            throw new InvalidArgumentException('Invalid status');
        }
        $stmt = $this->db->prepare('UPDATE users SET status = :status WHERE id = :id');
        $stmt->execute(['status' => $status, 'id' => $id]);
    }

    /** @return array{total:int, active:int} */
    public function counts(): array
    {
        $row = $this->db->query("SELECT COUNT(*) AS total, COALESCE(SUM(status = 'active'), 0) AS active FROM users")->fetch();
        return ['total' => (int) $row['total'], 'active' => (int) $row['active']];
    }
}
