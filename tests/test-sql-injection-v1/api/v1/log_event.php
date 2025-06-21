<?php
// File: api/v1/log_event.php
$configPath = __DIR__ . '/../../config.php';
if (file_exists($configPath)) { include $configPath; }
else { http_response_code(500); header('Content-Type: application/json'); echo json_encode(['error' => 'Config not found']); exit; }

header('Content-Type: application/json');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['error' => 'Method Not Allowed']); exit; }

$json_data = file_get_contents('php://input');
$data = json_decode($json_data, true);

$event_msg = isset($data['event_message']) ? $data['event_message'] : 'Default Event';
$user_agent = isset($data['user_agent']) ? $data['user_agent'] : '';

// --- LỖ HỔNG SQL INJECTION ---
// Tham số $user_agent từ JSON được đưa thẳng vào câu lệnh SQL
$query = "INSERT INTO logs (event_message, user_agent) VALUES ('$event_msg', '$user_agent')";
// ---------------------------

try {
    $pdo->exec($query);
    echo json_encode(['status' => 'success', 'message' => 'Event logged.']);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'Error related to SQL syntax.', // Thêm từ khóa "SQL syntax"
        'details' => $e->getMessage(),
        'debug_query' => $query
    ]);
}
?>