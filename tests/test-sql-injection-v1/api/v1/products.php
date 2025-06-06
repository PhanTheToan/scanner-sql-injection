<?php
$configPath = __DIR__ . '/../../config.php';
if (file_exists($configPath)) { include $configPath; }
else { http_response_code(500); header('Content-Type: application/json'); echo json_encode(['error' => 'Config not found']); exit; }

header('Content-Type: application/json');

$category = isset($_GET['category']) ? $_GET['category'] : '';

if (empty($category)) {
    http_response_code(400);
    echo json_encode(['error' => 'Category parameter is required.']);
    exit;
}

// --- LỖ HỔNG SQL INJECTION ---
$query = "SELECT product_id, name, price FROM products WHERE category = '$category'";
// ---------------------------

try {
    $stmt = $pdo->query($query);
    $products = $stmt->fetchAll(PDO::FETCH_ASSOC);
    echo json_encode(['status' => 'success', 'data' => $products]);
} catch (PDOException $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'A MySQL error occurred.', // Thêm từ khóa "MySQL"
        'details' => $e->getMessage()
    ]);
}
?>