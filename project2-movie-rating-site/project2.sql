
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS password_history;
DROP TABLE IF EXISTS movies;
DROP TABLE IF EXISTS movie_genres;
DROP TABLE IF EXISTS reviews;
DROP TABLE IF EXISTS genres;



CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    email_address TEXT UNIQUE NOT NULL,
    moderator INTEGER NOT NULL DEFAULT 0,
    critic INTEGER NOT NULL DEFAULT 0,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL
);


CREATE TABLE password_history (
    user_id INTEGER NOT NULL,
    password_hash TEXT NOT NULL,
    PRIMARY KEY (user_id, password_hash), 
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);


CREATE TABLE movies (
    movie_id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    synopsis TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE genres (
    genre_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL
);

CREATE TABLE movie_genres (
    movie_id INTEGER NOT NULL,
    genre_id INTEGER NOT NULL,
    FOREIGN KEY (movie_id) REFERENCES movies(movie_id) ON DELETE CASCADE,
    FOREIGN KEY (genre_id) REFERENCES genres(genre_id) ON DELETE CASCADE,
    PRIMARY KEY (movie_id, genre_id)
);


CREATE TABLE reviews (
    review_id INTEGER PRIMARY KEY,
    movie_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    rating INTEGER NOT NULL,
    text TEXT NOT NULL,
    FOREIGN KEY (movie_id) REFERENCES movies(movie_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

    