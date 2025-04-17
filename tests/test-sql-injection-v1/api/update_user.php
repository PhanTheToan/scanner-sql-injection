<?php
// File: api/update_user.php
$configPath = __DIR__ . '/../config.php';
if (file_exists($configPath)) { include $configPath; }
else { http_response_code(500); header('Content-Type: application/json'); echo json_encode(['status' => 'error', 'message' => 'Config file not found']); exit; }

header('Content-Type: application/json');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']); exit; }

$json_data = file_get_contents('php://input');
$data = json_decode($json_data, true);

if ($data === null && json_last_error() !== JSON_ERROR_NONE) { http_response_code(400); echo json_encode(['status' => 'error', 'message' => 'Invalid JSON data: ' . json_last_error_msg()]); exit; }

$user_id = isset($data['userId']) ? $data['userId'] : null;
$email = isset($data['email']) ? $data['email'] : null;
$description = isset($data['profile']['description']) ? $data['profile']['description'] : null;

if ($user_id === null || ($email === null && $description === null)) { http_response_code(400); echo json_encode(['status' => 'error', 'message' => 'Missing required fields (userId and email/profile.description)']); exit; }

// --- LỖ HỔNG SQL INJECTION ---
$update_part = '';
$query = "";
if ($email !== null) {
     $update_part = "SET email = '$email'"; // Inject email
     if ($user_id !== null) { $query = "UPDATE users $update_part WHERE id = $user_id"; } // Inject user_id
} elseif ($description !== null) {
     $update_part = "SET username = '$description'"; // Inject description vào username để test
     if ($user_id !== null) { $query = "UPDATE users $update_part WHERE id = $user_id"; } // Inject user_id
}
// ---------------------------

if (!empty($query)) {
    try {
        $affectedRows = $pdo->exec($query);
        if ($affectedRows > 0) { echo json_encode(['status' => 'success', 'message' => 'User updated successfully.']); }
        else { echo json_encode(['status' => 'success', 'message' => 'No changes made or user not found.']); }
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['status' => 'error', 'message' => 'Database Error: ' . $e->getMessage(), 'debug_query' => $query]);
    }
} else { http_response_code(400); echo json_encode(['status' => 'error', 'message' => 'Could not build update query.']); }
?>