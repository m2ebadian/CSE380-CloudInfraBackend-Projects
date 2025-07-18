-- Drop tables if they exist
DROP TABLE IF EXISTS products;

-- Products table
CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    price REAL NOT NULL,
    category TEXT NOT NULL
);