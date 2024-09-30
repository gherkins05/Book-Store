-- Already Done
CREATE EXTENSION IF NOT EXISTS pgcrypto;

--FUNCTIONS
CREATE OR REPLACE FUNCTION hash_password(password TEXT) RETURNS TEXT AS $$
BEGIN
    RETURN crypt(password, gen_salt('bf'));
END;
$$ LANGUAGE plpgsql;

--Completely wipe database
DROP SCHEMA public CASCADE;
CREATE SCHEMA public;

--TABLES

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL
);

CREATE TABLE books (
    id SERIAL PRIMARY KEY,
    title TEXT NOT NULL,
    author TEXT NOT NULL,
    genre TEXT NOT NULL,
    price DECIMAL(5,2) NOT NULL
);

CREATE TABLE user_books (
    user_id INTEGER,
    book_id INTEGER,
    PRIMARY KEY (user_id, book_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (book_id) REFERENCES books(id)
);

--Testing Functions
SELECT 
    u.id AS "User ID",
    u.name AS "User Name",
    u.username AS "Username",
    u.password AS "Password"
FROM users u;

SELECT 
    b.id AS "Book ID",
    b.title AS "Title",
    b.author AS "Author",
    b.genre AS "Genre",
    b.price AS "Price"
FROM books b;

SELECT
    u.id AS "User ID",
    u.username AS "Username",
    b.id AS "Book ID",
    b.title AS "Title"
FROM
    user_books ub
    JOIN users u ON ub.user_id = u.id
    JOIN books b ON ub.book_id = b.id
ORDER BY
    u.username,
    b.title;

SELECT
    b.id AS "Book ID",
    b.title AS "Title",
    b.author AS "Author",
    b.genre AS "Genre",
    b.price AS "Price"
FROM
    books b
    JOIN user_books ub ON b.id = ub.book_id
WHERE
    ub.user_id = 5
ORDER BY
    b.title;



--DATA

INSERT INTO users 
    (name, username, password)
VALUES
    ('John Doe', 'johnny', hash_password('password012')),
    ('Jane Doe', 'jane123', hash_password('password456')),
    ('Bob Stevens', 'bob456', hash_password('password678')),
    ('David Tanaka', 'tanakad', hash_password('password789')),
    ('Hollie Smart', 'hollsmart', hash_password('password123'));

INSERT INTO books 
    (title, author, price, genre)
VALUES
    ('Of Mice and Men', 'John Steinbeck', 8.99, 'Fiction'),
    ('Strange Case of Dr Jekyll and Mr Hyde', 'Robert Louis Stevenson', 9.99, 'Horror'),
    ('Romeo and Juliet', 'William Shakespeare', 5, 'Romance'),
    ('The Hunger Games', 'Suzanne Collins', 7.5, 'Science Fiction'),
    ('The Chronicles of Narnia', 'C. S. Lewis', 10.49, 'Fantasy'),
    ('The Confidence Men', 'Margalit Fox', 9.99, 'History');

INSERT INTO user_books 
    (user_id, book_id)
VALUES
    (5, 3),
    (5, 4),
    (5, 1),
    (5, 6),
    (2, 3),
    (3, 4),
    (1, 5),
    (3, 5),
    (2, 1),
    (2, 4),
    (5, 2),
    (1, 3),
    (4, 4),
    (3, 6),
    (3, 2);