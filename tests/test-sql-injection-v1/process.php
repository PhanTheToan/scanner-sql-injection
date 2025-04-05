<?php
include 'config.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];

    // Query dễ bị SQL Injection (không an toàn)
    $query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    
    try {
        $result = $pdo->query($query);

        if ($result->rowCount() > 0) {
            echo "<h2>Login Successful!</h2>";
            foreach ($result as $row) {
                echo "Welcome, " . htmlspecialchars($row['username']) . "!<br>";
            }
        } else {
            echo "<h2>Invalid Credentials</h2>";
        }
    } catch (PDOException $e) {
        echo "<h2>Error: " . htmlspecialchars($e->getMessage()) . "</h2>";
    }
}
?>
