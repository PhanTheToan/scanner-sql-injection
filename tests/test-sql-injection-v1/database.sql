CREATE DATABASE sql_injection_test;

USE sql_injection_test;

CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL
);

INSERT INTO users (username, password) VALUES 
('admin', 'admin123'),
('user1', 'password1'),
('user2', 'password2');

CREATE TABLE items (
    item_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category_id INT
);

INSERT INTO items (name, description, category_id) VALUES
('Laptop', 'A test laptop', 1),
('Keyboard', 'Mechanical keyboard', 1),
('Book', 'SQL Injection Explained', 2);

-- Bảng mới cho sản phẩm
CREATE TABLE products (
    product_id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100),
    price DECIMAL(10, 2)
);

INSERT INTO products (name, category, price) VALUES
('Super Widget', 'Widgets', 19.99),
('Mega Widget', 'Widgets', 29.99),
('Standard Gadget', 'Gadgets', 9.50);

-- Bảng mới để ghi log sự kiện (sẽ dùng cho API mới)
CREATE TABLE logs (
    log_id INT AUTO_INCREMENT PRIMARY KEY,
    event_message VARCHAR(255) NOT NULL,
    user_agent VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);