-- Drop the table if it exists
DROP TABLE IF EXISTS logs;

-- Create the logs table
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,         -- Type of event: user_creation, login, order, etc.
    username TEXT NOT NULL,      -- Username of the user who triggered the event
    name TEXT NOT NULL,          -- Product or category name, or 'NULL' as a string
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP -- Optional: to preserve log order
);
