<?php
session_start(); // Khởi động session để kiểm tra đăng nhập
include 'config.php'; // Include file kết nối CSDL

// --- Kiểm tra xem người dùng đã đăng nhập chưa ---
if (!isset($_SESSION['logged_in']) || $_SESSION['logged_in'] !== true) {
    // Nếu chưa đăng nhập, chuyển hướng về trang login hoặc báo lỗi
    // header("Location: /index.php");
    http_response_code(403); // Forbidden
    echo "<h2>Error: Access Denied. Please login first.</h2>";
    exit;
}

// --- Chỉ xử lý phương thức POST ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $update_data = isset($_POST['data']) ? $_POST['data'] : '';

    if (!empty($update_data)) {
        $user_id_to_update = 2;
        $query = "UPDATE users SET password = '$update_data' WHERE id = $user_id_to_update";
        // ---------------------------

        try {
            $affectedRows = $pdo->exec($query);

            if ($affectedRows > 0) {
                echo "<h2>Update Successful!</h2>";
                echo "<p>Data for user ID $user_id_to_update potentially updated (using injected value).</p>";
            } else {
                 echo "<h2>Update Executed.</h2>";
                 echo "<p>Query executed, but no rows affected (user ID $user_id_to_update might not exist or data was the same).</p>";
            }
             echo "<p>Executed Query (for debugging): " . htmlspecialchars($query) . "</p>"; // Hiển thị query để dễ debug
             echo '<p><a href="dashboard.php">Back to Dashboard</a></p>';

        } catch (PDOException $e) {
            echo "<h2>Error Updating Data: " . htmlspecialchars($e->getMessage()) . "</h2>";
            echo "<p>Failed Query (for debugging): " . htmlspecialchars($query) . "</p>";
             echo '<p><a href="dashboard.php">Back to Dashboard</a></p>';
        }
    } else {
        echo "<h2>Error: No data provided for update.</h2>";
        echo '<p><a href="dashboard.php">Back to Dashboard</a></p>';
    }
} else {
    // Nếu không phải POST, có thể chuyển hướng hoặc báo lỗi
    header("Location: dashboard.php"); // Quay lại dashboard nếu truy cập trực tiếp
    exit;
}
?>