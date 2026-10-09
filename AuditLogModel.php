<?php
/**
 * SECUREIAM | models/AuditLogModel.php
 * Insert-only audit logging. Search and report queries are added in Step 8.
 * The database triggers (schema.sql) make UPDATE/DELETE impossible.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

class AuditLogModel
{
    /**
     * Writes one audit event. Logging must never crash the request, so a failure
     * is reported to the PHP error log and the user flow continues.
     */
    public static function log(string $event, string $description, ?int $userId = null, ?string $email = null): void
    {
        try {
            $stmt = db()->prepare(
                'INSERT INTO audit_logs (user_id, actor_email, event_type, description, ip_address, user_agent)
                 VALUES (:user_id, :email, :event, :description, :ip, :agent)'
            );
            $stmt->execute([
                'user_id'     => $userId,
                'email'       => $email !== null ? mb_substr($email, 0, 150) : null,
                'event'       => $event,
                'description' => mb_substr($description, 0, 500),
                'ip'          => client_ip(),
                'agent'       => mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255),
            ]);
        } catch (PDOException $e) {
            error_log('Audit log write failed: ' . $e->getMessage());
        }
    }

    /** Newest events first. Search/report queries arrive in Step 8. */
    public static function recent(int $limit = 10): array
    {
        $stmt = db()->prepare(
            'SELECT id, user_id, actor_email, event_type, description, created_at
             FROM audit_logs ORDER BY id DESC LIMIT :lim'
        );
        $stmt->bindValue(':lim', $limit, PDO::PARAM_INT);   // LIMIT needs a real integer
        $stmt->execute();
        return $stmt->fetchAll();
    }
}
