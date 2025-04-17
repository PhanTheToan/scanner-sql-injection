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