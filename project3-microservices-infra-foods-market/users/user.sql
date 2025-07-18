-- DROP all tables if they exist
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS password_history;

-- USERS table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    email_address TEXT UNIQUE NOT NULL,
    employee INTEGER NOT NULL DEFAULT 0,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL
);

-- PASSWORD HISTORY table
CREATE TABLE password_history (
    user_id INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    PRIMARY KEY (user_id, password_hash),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
