const BOOK_URL = 'http://localhost:3000/books';
const USER_URL = 'http://localhost:3000/user';
const ADD_BOOK_URL = 'http://localhost:3000/add-book';
const REMOVE_BOOK_URL = 'http://localhost:3000/remove-book';
const BOOK_FILTER_URL = 'http://localhost:3000/bookFilter';
const booksElement = document.getElementById('books-container');
const bookTemplate = document.getElementById('book-template').children[0];

//Get all books using booksRequest
//Process the books using processBooks
//Get all readingList using userRequest
//Process the readingList using processReadingList

/*
Some improvements i could make:

Make it so the user has to log in to the use the rading List fitlers
Make it so the in-reading list descriptors are only shown when the user is logged in
Make it so the user can only add books to the reading list when logged in
Make it so the user can only remove books from the reading list when logged in
Make it so the user cant add the same book to the reading list more than once
*/

booksRequest().then(processBooks).catch(handleBookError);

async function booksRequest() {
    const response = await fetch(BOOK_URL, {
        headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('token')
        }
    });
    if (!response.ok) {
        throw response;
    }
    return await response.json();
}

function processBooks(books) {
    booksElement.innerHTML = '';
    for (const book of books) {
        booksElement.appendChild(generateBookElement(book));
    }
}

function generateBookElement(book) {
    let bookElement = bookTemplate.cloneNode(true);
    bookElement.classList.add(`bookID-${book.id}`);
    bookElement.querySelector('.book-header').textContent = book.title;
    bookElement.querySelector('.book-author').textContent = book.author;
    bookElement.querySelector('.book-genre').textContent = book.genre;
    bookElement.querySelector('.book-price').textContent = book.price;
    bookElement.querySelector('.book-id').textContent = book.id;

    bookElement.querySelector('.add-book').addEventListener('click', addBook);
    bookElement.querySelector('.remove-book').addEventListener('click', removeBook);
    return bookElement;
}

function handleBookError(error) {
    console.log(error);
    document.getElementById('account-name').innerHTML = 'Log In';
}

async function fetchUser() {
    const response = await fetch(USER_URL, {
        headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('token')
        }
    });
    if (!response.ok) {
        throw response;
    }
    return await response.json();
}


function processUser(user) {
    document.getElementById('login-identifier').classList.add('login-success');
    document.getElementById('login-identifier').classList.remove('login-failed');
    document.getElementById('account-name').innerHTML = user.username;
    console.log(user.readingList);
    processReadingList(user.readingList);
}

function processReadingList(readingList) {
    const booksContainer = document.getElementById('books-container');
    for (const book of readingList.rows) {
        console.log(`Book ID: ${book.id} Title: ${book.title} Genre: ${book.genre} Author: ${book.author} Price: ${book.price}`);
        //Get book card and change background to be green
        const bookElement = booksContainer.querySelector(`.bookID-${book.id}`);
        bookElement.classList.add('in-reading-list');
        bookElement.classList.remove('not-in-reading-list');
    }
}

function handleUserError(error) {
    console.log(error);
    document.getElementById('account-name').innerHTML = 'Log In';
    document.getElementById('login-identifier').classList.remove('login-success');
    document.getElementById('login-identifier').classList.add('login-failed');
}

fetchUser().then(processUser).catch(handleUserError);

function getBookInformation(target) {
    const bookElement = target.closest('.book-container');
    const bookID = bookElement.querySelector('.book-id').textContent;
    const bookTitle = bookElement.querySelector('.book-header').textContent;
    const bookAuthor = bookElement.querySelector('.book-author').textContent;
    const bookGenre = bookElement.querySelector('.book-genre').textContent;
    const bookPrice = bookElement.querySelector('.book-price').textContent;

    const book = {
        id: bookID,
        title: bookTitle,
        author: bookAuthor,
        genre: bookGenre,
        price: bookPrice
    };

    return book;
}



function addBook(event) {
    const bookID = getBookInformation(event.target).id;
    const bookData = { bookID };
    sendAddBook(bookData).then(processAddBookResponse).catch(handleAddBookError);

}

async function sendAddBook(bookData) {
    const response = await fetch(ADD_BOOK_URL, {
        method: 'POST', // Change the method to 'POST'
        headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('token'),
            'Content-Type': 'application/json' // Set the content type to 'application/json'
        },
        body: JSON.stringify(bookData) // Add the body property
    });
    if (!response.ok) {
        throw response;
    }
    const data = await response.json(); // Parse the response body as JSON
    console.log(data); // Log the parsed data
    return data;
}

function processAddBookResponse(response) {}

async function handleAddBookError(error) {
    const errorResponse = await error.json();
    console.log(errorResponse.error);
}



function removeBook(event) {
    const bookID = getBookInformation(event.target).id;
    const bookData = { bookID };
    sendRemoveBook(bookData).then(processRemoveBookResponse).catch(handleRemoveBookError);
}

async function sendRemoveBook(bookData) {
    const response = await fetch(REMOVE_BOOK_URL, {
        method: 'POST', // Change the method to 'POST'
        headers: {
            'Authorization': 'Bearer ' + localStorage.getItem('token'),
            'Content-Type': 'application/json' // Set the content type to 'application/json'
        },
        body: JSON.stringify(bookData) // Add the body property
    });
    if (!response.ok) {
        throw response;
    }
    const data = await response.json(); // Parse the response body as JSON
    console.log(data); // Log the parsed data
    return data;
}

function processRemoveBookResponse(response) {
    const bookID = response.bookID;
    const bookElement = booksElement.querySelector(`.bookID-${bookID}`);
    bookElement.classList.remove('in-reading-list');
    bookElement.classList.add('not-in-reading-list');
}

async function handleRemoveBookError(error) {
    const errorResponse = await error.json();
    console.log(errorResponse.error);
}

async function sendFilterBooks(filters) {
    const response = await fetch(BOOK_FILTER_URL, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(filters),
    });
    if (!response.ok) {
        throw new Error('Error fetching books');
    }
    const books = await response.json();
    return books;
}

function processFilterBooksResponse(response) {
    processBooks(response);
    console.log("NEW FILTER -------------------------------");
    for (const book of response) {
        console.log(book);
    }
}

async function handleFilterBooksError(error) {
    const errorResponse = await error.json();
    console.log(errorResponse.error);
}

function applyFilter() {
    //Getting Filters
    const checkBoxes = document.querySelectorAll('.book-filter-selector:checked');
    
    const myReadingListCheckbox = document.getElementById('MRL-FLS');
    const notMyReadingListCheckbox = document.getElementById('NMRL-FLS');

    const readingList = myReadingListCheckbox.checked ? 'myReadingList' 
                        : notMyReadingListCheckbox.checked ? 'notMyReadingList' 
                        : 'allBooks';
    
    const selectedGenres = [];
    for (const checkBox of checkBoxes) {
        selectedGenres.push(checkBox.value);
    }
    //Format Filters
    const filters = {
        genre: selectedGenres
    }


    //Send Filters
    sendFilterBooks(filters).then(processFilterBooksResponse).catch(handleFilterBooksError);

}


function addFilterLogic() {
    const filterCheckboxes = document.querySelectorAll('.book-filter-selector');
    for (const checkbox of filterCheckboxes) {
        checkbox.addEventListener('change', checkBoxChange);
    }
}

function checkBoxChange(event) {
    const checkBox = event.target;
    const filterParent = checkBox.closest('.book-filter-list');

    //Now need to apply new filter logic
    applyFilter();
}

addFilterLogic();