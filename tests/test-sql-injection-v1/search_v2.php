<!DOCTYPE html>
<html lang="en">
<head> <title>Advanced Search</title> </head>
<body>
    <h1>Advanced Item Search</h1>
    <form action="" method="GET">
        <input type="text" name="q" placeholder="Search query..." value="<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>">
        <select name="sort_order">
            <option value="ASC" <?php if(($_GET['sort_order'] ?? '') == 'ASC') echo 'selected'; ?>>Ascending</option>
            <option value="DESC" <?php if(($_GET['sort_order'] ?? '') == 'DESC') echo 'selected'; ?>>Descending</option>
        </select>
        <button type="submit">Search</button>
    </form>

    <?php
    if (isset($_GET['q'])) {
        include 'config.php';
        $search_term = $_GET['q'];
        // --- LỖ HỔNG SQL INJECTION ---
        // Tham số sort_order được đưa thẳng vào ORDER BY
        $sort_order = $_GET['sort_order'] ?? 'ASC';
        $query = "SELECT name, description FROM items WHERE name LIKE '%$search_term%' ORDER BY name $sort_order";
        // ---------------------------

        echo "<h4>Results:</h4><pre>Query: " . htmlspecialchars($query) . "</pre>";
        try {
            $stmt = $pdo->query($query);
            echo "<ul>";
            while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
                echo "<li><strong>" . htmlspecialchars($row['name']) . ":</strong> " . htmlspecialchars($row['description']) . "</li>";
            }
            echo "</ul>";
        } catch (PDOException $e) {
            // Lỗi này sẽ được hiển thị trên trang HTML và máy quét sẽ phát hiện được
            echo "<h2>Error: " . htmlspecialchars($e->getMessage()) . "</h2>";
        }
    }
    ?>
</body>
</html>