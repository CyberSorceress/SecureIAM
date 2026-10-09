<?php if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); } ?>
<div class="auth-shell">
    <div class="auth-hero d-none d-lg-flex">
        <div>
            <div class="auth-logo"><i class="bi bi-shield-lock-fill"></i> <?= e(APP_NAME) ?></div>
            <h2>Secure access to every <?= e(COMPANY_NAME) ?> system.</h2>
            <ul class="list-unstyled auth-points">
                <li><i class="bi bi-check-circle-fill"></i> Role-based access control</li>
                <li><i class="bi bi-check-circle-fill"></i> Approval workflows</li>
                <li><i class="bi bi-check-circle-fill"></i> Complete audit trail</li>
            </ul>
        </div>
    </div>
    <div class="auth-panel">
        <div class="auth-card">
            <h1 class="h4 mb-1">Sign in</h1>
            <p class="text-muted mb-4">Use your <?= e(COMPANY_NAME) ?> work account.</p>

            <?= render_flash() ?>
            <?php if (!empty($error)): ?>
                <div class="alert alert-danger" role="alert"><?= e($error) ?></div>
            <?php endif; ?>

            <form method="post" action="<?= e(url('login')) ?>">
                <?= csrf_field() ?>
                <div class="mb-3">
                    <label for="email" class="form-label">Email</label>
                    <input type="email" class="form-control" id="email" name="email" maxlength="150"
                           value="<?= e($oldEmail ?? '') ?>" autocomplete="username" required autofocus>
                </div>
                <div class="mb-2">
                    <label for="password" class="form-label">Password</label>
                    <div class="input-group">
                        <input type="password" class="form-control" id="password" name="password"
                               maxlength="255" autocomplete="current-password" required>
                        <button class="btn btn-outline-secondary" type="button" data-toggle-password="#password" aria-label="Show password">
                            <i class="bi bi-eye"></i>
                        </button>
                    </div>
                </div>
                <div class="text-end mb-3"><a href="<?= e(url('forgot')) ?>" class="small">Forgot password?</a></div>
                <button type="submit" class="btn btn-primary w-100">Sign in</button>
            </form>
            <p class="text-center mt-4 mb-0 small">No account? <a href="<?= e(url('register')) ?>">Register</a></p>
        </div>
    </div>
</div>
