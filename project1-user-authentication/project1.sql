-- Drop tables if they exist to reset the database
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS password_history;


-- Create the users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    email_address TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL
);

-- Create the password history table to store previously used passwords
CREATE TABLE password_history (
    user_id INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    PRIMARY KEY (user_id, password_hash), -- Prevents duplicate entries
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);


