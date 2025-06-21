<?php
// File: api/search_items.php
$configPath = __DIR__ . '/../config.php';
if (file_exists($configPath)) { include $configPath; }
else { http_response_code(500); header('Content-Type: application/json'); echo json_encode(['status' => 'error', 'message' => 'Config file not found']); exit; }

header('Content-Type: application/json');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); echo json_encode(['status' => 'error', 'message' => 'Method Not Allowed']); exit; }

$search_query = isset($_POST['query']) ? $_POST['query'] : '';
$category_id = isset($_POST['category_id']) ? $_POST['category_id'] : null;

// --- LỖ HỔNG SQL INJECTION ---
// Cần có bảng items(item_id, name, description, category_id) trong DB
$where_clauses = ["name LIKE '%$search_query%'"]; // Inject query
if ($category_id !== null && $category_id !== '') { $where_clauses[] = "category_id = $category_id"; } // Inject category_id (chỉ thêm nếu có giá trị)
$where_sql = implode(' AND ', $where_clauses);
$query = "SELECT item_id, name FROM items WHERE $where_sql";
// ---------------------------

try {
    $stmt = $pdo->query($query); // Thực thi query
    $items = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode(['status' => 'success', 'data' => $items]);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode(['status' => 'error', 'message' => 'Database Error: ' . $e->getMessage()]);
}
?>