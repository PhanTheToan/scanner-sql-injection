<?php
// File: api/get_user.php
$configPath = __DIR__ . '/../config.php';
if (file_exists($configPath)) { include $configPath; }
else { http_response_code(500); header('Content-Type: application/json'); echo json_encode(['status' => 'error', 'message' => 'Config file not found']); exit; }

$user_id = isset($_GET['id']) ? $_GET['id'] : null;

if ($user_id !== null) {
    // --- LỖ HỔNG SQL INJECTION ---
    $query = "SELECT id, username FROM users WHERE id = $user_id";
    // ---------------------------
    try {
        $stmt = $pdo->query($query);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        header('Content-Type: application/json');
        if ($user) { echo json_encode(['status' => 'success', 'data' => $user]); }
        else { http_response_code(404); echo json_encode(['status' => 'error', 'message' => 'User not found']); }
    } catch (PDOException $e) {
        http_response_code(500); header('Content-Type: application/json');
        echo json_encode(['status' => 'error', 'message' => 'Database Error: ' . $e->getMessage()]);
    }
} else {
    http_response_code(400); header('Content-Type: application/json');
    echo json_encode(['status' => 'error', 'message' => 'Missing required parameter: id']);
}
?>