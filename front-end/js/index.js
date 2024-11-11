function loginAttempt() {
    const username = document.getElementById('username-input').value;
    const password = document.getElementById('password-input').value;

    fetch('http://localhost:3000/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        },
        body: JSON.stringify({ username, password })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.token) {
            localStorage.setItem('token', data.token);
            window.location.href = '/home';
        } else {
            const error = document.getElementById('login-error');
            error.innerHTML = data.message;
            console.log("Error logging in: ", data.message);
        }
    });
}

// Recreated loginAttempt using async and await

/*

async function loginAttempt() {
    const username = document.getElementById('username-input').value;
    const password = document.getElementById('password-input').value;

    try {
        const response = await fetch('http://localhost:3000/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({ username, password })
        });

        if (!response.ok) { throw new Error(`HTTP error! status: ${response.status}`); }

        const data = await response.json();

        if (data.token) {
            localStorage.setItem('token', data.token);
            window.location.href = '/home';
        } else {
            const error = document.getElementById('login-error');
            error.innerHTML = data.message;
            console.log("Error logging in: ", data.message);
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

*/
