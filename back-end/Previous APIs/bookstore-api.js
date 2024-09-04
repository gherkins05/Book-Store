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

app.get('/', (req, res) => {
    res.send('Hello, World!');
});

const port = 3000;

app.listen(port, () => console.log(`Server running on port ${port}`));

function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    console.log('Auth Header: ' + authHeader);


    if (!authHeader || !authHeader.includes(' ')) {
        return res.sendStatus(401); // If there's no Authorization header or it doesn't contain a space, return a 401 Unauthorized status
    }

    const token = authHeader && authHeader.split(' ')[1];

    console.log('Token: ' + token);

    if (token == null) {
        return res.sendStatus(401); // If there's no token, return a 401 Unauthorized status
    }

    jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
        if (err) {
            return res.sendStatus(403); // If the token is invalid, return a 403 Forbidden status
        }
        console.log(user);
        req.user = user; // Attach the user object to the request
        next(); // Pass control to the next middleware function
    });
}
const { Pool } = require('pg');
const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'bookstore',
    password: process.env.DB_PASSWORD,
    port: 5432,
});

app.post('/bookFilter', async (req, res) => {
    try {
        const filters = req.body; // Get the filters from the request body

        // Start building the query
        let query = 'SELECT * FROM books';
        let queryParams = [];
        let filterStrings = [];

        // Loop over the filters and add them to the query
        for (let [field, value] of Object.entries(filters)) {
            if (Array.isArray(value) && value.length > 0) {
                // If the value is an array, generate an IN clause
                let placeholders = value.map((_, i) => `$${queryParams.length + i + 1}`).join(', ');
                filterStrings.push(`${field} IN (${placeholders})`);
                queryParams.push(...value);
            } else {
                filterStrings.push(`${field} = $${queryParams.length + 1}`);
                queryParams.push(value);
            }
        }

        // If there are any filters, add a WHERE clause to the query
        if (filterStrings.length > 0) {
            query += ' WHERE ' + filterStrings.join(' AND ');
        }
        // Run the query
        const result = await pool.query(query, queryParams);

        // Send the result
        res.send(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).send('Error running query');
    }
});

app.get('/user', authenticate, async (req, res) => {
    try {
        const resultUsername = await pool.query('SELECT username FROM users WHERE id = $1', [req.user.id]);
        const resultReadingList = await pool.query('SELECT b.id, b.title, b.genre, b.author, b.price FROM books b JOIN user_books ub ON b.id = ub.book_id WHERE ub.user_id = $1 ORDER BY b.title', [req.user.id]);
        if (resultUsername.rows.length > 0) {
            res.send({ username: resultUsername.rows[0].username, readingList: resultReadingList });
            console.log("Data sent");
        } else {
            res.status(404).send({ error: 'User not found' });
        }
    } catch (err) {
        console.error(err);
        res.send('Error running query');
    }
});



app.get('/books', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM books');
        res.send(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Error running query', details: err.message });
    }
});


app.post('/add-book', authenticate, async (req, res) => {
    const userId = req.user.id;
    const { bookID } = req.body;

    console.log(`userId: ${userId}, bookID: ${bookID}`);

    if (!userId || !bookID) {
        return res.status(400).send({ error: 'userId and bookID are required' });
    }

    try {
        const result = await pool.query('SELECT * FROM user_books WHERE user_id = $1 AND book_id = $2', [userId, bookID]);
        if (result.rows.length > 0) {
            console.log('Book alrady in reading list');
            res.status(400).send({ error: 'Book already in reading list' });
        } else {
            await pool.query('INSERT INTO user_books (user_id, book_id) VALUES ($1, $2)', [userId, bookID]);
            res.send({ success: true, message: 'Book added to reading list' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Error running query', details: err.message });
    }
});

app.post('/remove-book', authenticate, async (req, res) => {
    const userId = req.user.id;
    const { bookID } = req.body;

    console.log(`userId: ${userId}, bookID: ${bookID}`);

    if (!userId || !bookID) {
        return res.status(400).send({ error: 'userId and bookID are required' });
    }

    try {
        const result = await pool.query('SELECT * FROM user_books WHERE user_id = $1 AND book_id = $2', [userId, bookID]);
        if (result.rows.length == 0) {
            console.log('Book isnt in reading list');
            res.status(400).send({ error: 'Book isnt in reading list' });
        } else {

            await pool.query('DELETE FROM user_books WHERE user_id = $1 AND book_id = $2', [userId, bookID]);
            console.log(`Removed book ${bookID} from  ${userId}'s reading list`);
            res.send({ success: true, message: 'Book removed from reading list' });
        }
    } catch (err) {
        console.error(err);
        res.status(500).send({ error: 'Error running query', details: err.message });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Checks if the username exists in the given table
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        // If the user doesnt exist, returns an error
        if (!user) {
            return res.status(400).send({ success: false, message: 'Invalid username or password' });
        }

        // Checks if the password matches the hashed password in the table
        const result2 = await pool.query('SELECT (password = crypt($1, password)) AS password_match FROM users WHERE username = $2', [password, username]);
        const passwordMatch = result2.rows[0].password_match;

        // If the password doesnt match, returns an error
        if (!passwordMatch) {
            return res.status(400).send({ success: false, message: 'Invalid username or password' });
        }

        // If the password matches, generate a token and send it in the response
        const token = jwt.sign({ id: user.id }, process.env.SECRET_KEY, { expiresIn: '10m' });
        res.send({ success: true, token });

    } catch (err) {
        console.error(err);
        res.status(500).send('Error running query');
    }
});
