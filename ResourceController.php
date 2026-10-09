<?php
/**
 * SECUREIAM | controllers/ResourceController.php
 * Create / edit protected resources. Route permission: MANAGE_RESOURCES.
 *
 * BURP DEMO (Mass assignment): add is_system=1 to the create request.
 * Expected: ignored, the resource is created as a normal one.
 * BURP DEMO (Access control): POST an edit for the SecureIAM Console resource id.
 * Expected: refused and logged.
 */
if (!defined('SECUREIAM')) { http_response_code(403); exit('Forbidden'); }

class ResourceController
{
    private const SENSITIVITY = ['low', 'medium', 'high'];
    private const STATUSES    = ['active', 'inactive'];

    private ResourceModel $resources;

    public function __construct()
    {
        $this->resources = new ResourceModel();
    }

    public function index(): void
    {
        if ($_SERVER['REQUEST_METHOD'] === 'POST') {
            $this->handlePost(get_string('action'));
            return;
        }
        render('resources/index', [
            'pageTitle' => 'Resource Management',
            'resources' => $this->resources->all(),
        ]);
    }

    private function handlePost(string $action): void
    {
        match ($action) {
            'create' => $this->create(),
            'edit'   => $this->edit(),
            default  => render_error(404),
        };
    }

    /** @return array{0:string,1:string,2:string,3:string} name, description, sensitivity, status */
    private function readFields(): array
    {
        $name        = trim(post_string('name'));
        $description = trim(post_string('description'));
        $sensitivity = post_string('sensitivity');
        $status      = post_string('status') === '' ? 'active' : post_string('status');

        if (!is_valid_label($name) || !is_valid_description($description)
            || !in_array($sensitivity, self::SENSITIVITY, true) || !in_array($status, self::STATUSES, true)) {
            $this->fail('Enter a valid name, description, sensitivity and status.');
        }
        return [$name, $description, $sensitivity, $status];
    }

    private function create(): void
    {
        [$name, $description, $sensitivity] = $this->readFields();
        if ($this->resources->create($name, $description, $sensitivity) === null) {
            $this->fail('A resource with that name already exists.');
        }
        AuditLogModel::log('RESOURCE_CREATE', 'Created resource ' . $name . ' (sensitivity: ' . $sensitivity . ')', current_user_id(), $_SESSION['user_email']);
        flash_set('success', 'Resource created. Add permissions for it on the Permissions page.');
        redirect('resources');
    }

    private function edit(): void
    {
        $resource = $this->resources->findById(post_int('resource_id'));
        if ($resource === null) {
            $this->fail('Resource not found.');
        }
        if ((int) $resource['is_system'] === 1) {
            AuditLogModel::log('ACCESS_DENIED', 'Attempt to edit system resource ' . $resource['name'], current_user_id(), $_SESSION['user_email']);
            $this->fail('The system resource cannot be modified.');
        }

        [$name, $description, $sensitivity, $status] = $this->readFields();
        if (!$this->resources->update((int) $resource['id'], $name, $description, $sensitivity, $status)) {
            $this->fail('Another resource already uses that name.');
        }
        AuditLogModel::log('RESOURCE_EDIT', 'Edited resource ' . $resource['name'] . ' (now: ' . $name . ', ' . $sensitivity . ', ' . $status . ')', current_user_id(), $_SESSION['user_email']);
        flash_set('success', 'Resource updated.');
        redirect('resources');
    }

    private function fail(string $message): void
    {
        flash_set('danger', $message);
        redirect('resources');
    }
}
