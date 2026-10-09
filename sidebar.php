<?php
/**
 * SECUREIAM | includes/sidebar.php
 * Menu generated from the SAME route table that index.php enforces: a link appears only if
 * the page exists AND the user holds the permission that page requires.
 * REMINDER: a hidden link is cosmetics; the server-side check in index.php is the real control.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

$currentPage = get_string('page');
$routeTable  = $GLOBALS['routes'] ?? [];

$navItem = static function (string $page, string $icon, string $label) use ($currentPage, $routeTable): string {
    if (!isset($routeTable[$page])) {
        return '';   // page not built yet
    }
    $needed = $routeTable[$page][3] ?? null;
    if ($needed !== null && !has_permission($needed)) {
        return '';
    }
    $active = $currentPage === $page ? ' active' : '';
    return '<a class="nav-link' . $active . '" href="' . e(url($page)) . '"><i class="bi ' . e($icon) . '"></i> ' . e($label) . '</a>';
};

$sections = [
    'Main'     => [['dashboard', 'bi-speedometer2', 'Dashboard']],
    'Access'   => [['requests', 'bi-key', 'Request Access'], ['approvals', 'bi-check2-square', 'Approvals']],
    'Admin'    => [['users', 'bi-people', 'Users'], ['roles', 'bi-person-badge', 'Roles'],
                   ['permissions', 'bi-shield-check', 'Permissions'], ['resources', 'bi-hdd-network', 'Resources']],
    'Security' => [['audit', 'bi-journal-text', 'Audit Logs'], ['auditor', 'bi-shield-exclamation', 'Security Dashboard']],
];
?>
<aside class="sidebar" id="sidebar">
    <div class="sidebar-brand"><i class="bi bi-shield-lock-fill"></i> <?= e(APP_NAME) ?><small><?= e(COMPANY_NAME) ?></small></div>
    <nav class="nav flex-column">
        <?php foreach ($sections as $heading => $items): ?>
            <?php
            $links = '';
            foreach ($items as [$page, $icon, $label]) {
                $links .= $navItem($page, $icon, $label);
            }
            ?>
            <?php if ($links !== ''): ?>
                <div class="nav-heading"><?= e($heading) ?></div>
                <?= $links ?>
            <?php endif; ?>
        <?php endforeach; ?>
        <div class="nav-heading">Account</div>
        <?= $navItem('password', 'bi-key-fill', 'Change password') ?>
        <form method="post" action="<?= e(url('logout')) ?>">
            <?= csrf_field() ?>
            <button class="nav-link btn btn-link text-start w-100" type="submit"><i class="bi bi-box-arrow-right"></i> Logout</button>
        </form>
    </nav>
</aside>
