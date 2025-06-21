<?php
$host = 'localhost';
$dbname = 'sql_injection_test';
$username = 'admin';
$password = '123456';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    echo "Connection successful!<br>";

    // Query the users table
    $stmt = $pdo->query("SELECT * FROM users");
    while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) {
        echo "ID: " . $row['id'] . ", Username: " . $row['username'] . ", Password: " . $row['password'] . "<br>";
    }
} catch (PDOException $e) {
    die("Connection failed: " . $e->getMessage() . " | Code: " . $e->getCode() . " | File: " . $e->getFile() . " | Line: " . $e->getLine());
}
?>