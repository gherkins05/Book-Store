require('dotenv').config();
const cors = require('cors');
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const rateLimit = require('express-rate-limit');

const app = express();

// Set up rate limit
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
});

// Apply the rate limit to all requests
app.use(limiter);

// parse application/json
app.use(bodyParser.json());

var corsOptions = {
    origin: 'http://127.0.0.1:5500',
    optionsSuccessStatus: 200 // some legacy browsers (IE11, various SmartTVs) choke on 204
}

app.use(cors(corsOptions));

const port = 3000;

const { Pool } = require('pg');

const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'bookstore',
    password: process.env.DB_PASSWORD,
    port: 5432,
});

app.listen(port, () => console.log(`Server running on port ${port}`));

// Middleware to enforce JSON Accept header
app.use((req, res, next) => {
    if (req.headers.accept.indexOf('application/json') === -1) {
        return res.status(406).send('Not Acceptable');
    }
    next();
});

// Middleware to enforce JSON Content-Type header
app.use((req, res, next) => {
    if (req.method === 'POST' || req.method === 'PUT') {
        if (!req.is('application/json')) {
            return res.status(415).send('Unsupported Media Type');
        }
    }
    next();
});

// AUTHENTICATION TOKEN VALIDATION
function authenticate(errorCode, errorMessage) {
    return function (req, res, next) {
        // Gets the Authorization header
        const authHeader = req.headers.authorization;
        console.log('Auth Header: ' + authHeader);

        // Checks for a valid Authorization header
        if (!authHeader || !authHeader.includes(' ')) {
            return res.status(errorCode || 401).send(errorMessage || 'Unauthorized');
        }

        // Splits the header into an array and gets the token
        const token = authHeader && authHeader.split(' ')[1];

        // Checks for a valid token
        if (token == null) {
            return res.status(errorCode || 401).send(errorMessage || 'Unauthorized');
        }

        // Verifies the token
        jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
            if (err) {
                return res.status(errorCode || 403).send(errorMessage || 'Forbidden');
            }

            // Attaches the user object to the request
            req.user = user;

            // Passes control to the next middleware function
            next();
        });
    }
}

// PASSWORD REQUIREMENTS CHECKER

function validatePassword(password, username) {
    if (password.length < 8) {
        return 'Password must be at least 8 characters long.';
    }

    if (!/[A-Z]/.test(password) || !/[a-z]/.test(password) || !/[0-9]/.test(password) || !/[^A-Za-z0-9]/.test(password)) {
        return 'Password must include at least one uppercase letter, one lowercase letter, one number, and one special character.';
    }

    if (password.includes(username)) {
        return 'Password should not include your username.';
    }

    const commonPasswords = ['password', '12345678', 'qwerty', 'admin']; // Add more common passwords
    if (commonPasswords.includes(password)) {
        return 'Password is too common.';
    }

    return null;
}


// REGISTER -------------------------------

app.post('/api/register', async (req, res) => {
    const { name, username, password } = req.body;

    // Check if any of the fields are missing
    if (!name || !username || !password) {
        return res.status(400).send({ message: 'Validation failed. Please check your input and try again' });
    }

    try {
        // Check if user alredy exists
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length > 0) {
            return res.status(409).send({ message: 'A user with this username already exists.' });
        }

        // Add check for password criteria
        const passwordError = validatePassword(password, username);
        if (passwordError) {
            return res.status(400).send(passwordError);
        }

        // Add the data to the database
        await pool.query('INSERT INTO users (name, username, password) VALUES ($1, $2, hash_password($3))', [name, username, password]);

        // Get user ID
        const result2 = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result2.rows[0];

        // Generate token
        const token = jwt.sign({ id: user.id }, process.env.SECRET_KEY, { expiresIn: '10m' });

        // Send a success response
        return res.status(201).send({ token: token });

    } catch (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
    }
});

// LOGIN ----------------------------------

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;


    // Check if any of the fields are missing
    if (!username || !password) {
        return res.status(400).send({ message: 'Validation failed. Please check your input and try again' });
    }

    try {
        // Check if the username exists in the given table
        const usernameResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = usernameResult.rows[0];

        // If none found, return error
        if (usernameResult.rows.length === 0) {
            return res.status(401).send({ message: 'Invalid username' });
        }

        // Check if the password is correct
        const passwordResult = await pool.query('SELECT (password = crypt($2, password)) AS password_match FROM users WHERE username = $1', [username, password]);
        const passwordMatch = passwordResult.rows[0].password_match;

        // If none found, return error
        if (!passwordMatch) {
            return res.status(401).send({ message: 'Invalid username or password' });
        }

        // Create and send token
        const token = jwt.sign({ id: user.id }, process.env.SECRET_KEY, { expiresIn: '10m' });

        return res.status(200).send({ token: token });


    } catch (err) {
        console.error(err);
        return res.status(500).send('Internal Server Error');
    }
});

// LOGOUT ---------------------------------

app.post('/api/logout', authenticate(401, 'You are not logged in'), async (req, res) => {

    // Send a success response
    res.status(200).send({ message: 'User logged out successfully.' });

});

// BOOKS ----------------------------------

app.get('/api/books', authenticate(), async (req, res) => {
    try {
        // Get all books
        const books = await pool.query('SELECT * FROM books');

        // Send the books as a response
        res.status(200).send(books.rows);

    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Error running query', details: err.message });
    }
});


// SINGLE BOOK ----------------------------

app.get('/api/books/:id', authenticate(), async (req, res) => {
    const { id } = req.params;

    try {
        // Get book with the given ID
        const book = await pool.query('SELECT * FROM books WHERE id = $1', [id]);

        //Check if book exists
        if (book.rows.length === 0) {
            return res.status(404).send({ message: 'Book not found' });
        }

        // Send the book as a response
        res.status(200).send(book.rows[0]);

    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Error running query', details: err.message });
    }
});

// READING LIST ---------------------------

app.get('/api/users/:userId/reading-list', authenticate(401, { message: 'You do not have permission to view this reading list.' }), async (req, res) => {
    const userId = req.params.userId;

    try {
        // Get all books in user's reading list
        const readingList = await pool.query('SELECT * FROM user_books WHERE user_id = $1 ORDER BY book_id', [userId]);

        // Send reading list
        res.status(200).send(readingList.rows);

    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Error running query', details: err.message });
    }
});

// ADD BOOK TO READING LIST ---------------

app.post('/api/users/:userId/reading-list', authenticate(401, { message: 'You do not have permission to edit this reading list.' }), async (req, res) => {
    const userId = req.params.userId;
    const { book_id } = req.body;

    // Check if any of the fields are missing
    if (!book_id) {
        return res.status(400).send({ message: 'Validation failed. Please check your input and try again' });
    }

    try {
        // Check if book already in reading list
        const readingList = await pool.query('SELECT * FROM user_books WHERE user_id = $1 AND book_id = $2', [userId, book_id]);

        // Send error if book already in reading list
        if (readingList.rows.length > 0) {
            return res.status(409).send({ message: 'This book already exists in your reading list.' });
        }

        // Add book to reading list
        await pool.query('INSERT INTO user_books (user_id, book_id) VALUES ($1, $2)', [userId, book_id]);

        // Create success response
        const repsonse = {
            book_id: book_id,
            created_at: new Date()
        }

        // Send success response
        res.status(201).send(repsonse);


    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Error running query', details: err.message });
    }
});

// REMOVE BOOK FROM READING LIST ----------

app.delete('/api/users/:userId/reading-list/:bookId', authenticate(401, { message: 'You do not have permission to edit this reading list.' }), async (req, res) => {
    const userId = req.params.userId;
    const bookId = req.params.bookId;

    try {
        // Check if book exists in reading list
        const readingList = await pool.query('SELECT * FROM user_books WHERE user_id = $1 AND book_id = $2', [userId, bookId]);

        // Send error if book not in reading list
        if (readingList.rows.length === 0) {
            return res.status(404).send({ message: 'This book does not exist in your reading list.' });
        }

        // Remove book from reading list
        await pool.query('DELETE FROM user_books WHERE user_id = $1 AND book_id = $2', [userId, bookId]);

        // Send success response
        res.status(204).send();
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Error running query', details: err.message });
    }
});

// GET USER PROFILE

app.get('/api/users/:userId', authenticate(401, { message: 'You do not have permission to view this user profile.' }), async (req, res) => {
    const userId = req.params.userId;

    try {
        // Get user profile
        const user = await pool.query('SELECT id, name, username FROM users WHERE id = $1', [userId]);

        // Send user profile
        res.status(200).send(user.rows[0]);

    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Error running query', details: err.message });
    }
});

// UPDATE USER PROFILE

app.patch('/api/users/:userId', authenticate(401, { message: 'You do not have permission to view this user profile.' }), async (req, res) => {
    const userId = req.params.userId;
    const { name, username } = req.body;

    // Check if any of the fields are missing 
    if (!name && !username) {
        return res.status(400).send({ message: 'Validation failed. Please check your input and try again' });
    }

    try {
        // Update user profile
        // Update username
        if (username) {
            await pool.query('UPDATE users SET username = $1 WHERE id = $2', [username, userId]);
        }

        // Update name
        if (name) {
            await pool.query('UPDATE users SET name = $1 WHERE id = $2', [name, userId]);
        }

        // Send success response
        res.status(200).send({ message: 'User profile updated successfully.' });

    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Error running query', details: err.message });
    }
});