let basicAuth = null;
document.getElementById('loginForm').onsubmit = async function(e) {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    basicAuth = 'Basic ' + btoa(`${username}:${password}`);
    document.getElementById('loginError').textContent = '';
    try {
        const res = await fetch('/api/users', { headers: { Authorization: basicAuth } });
        if (res.ok) {
            document.getElementById('loginForm').style.display = 'none';
            document.getElementById('usersTable').style.display = '';
            const users = await res.json();
            const tbody = document.querySelector('#users tbody');
            tbody.innerHTML = users.map(u => `<tr><td>${u.id}</td><td>${u.name}</td><td>${u.surname}</td><td>${u.age}</td></tr>`).join('');
        } else {
            let message = 'Invalid credentials or server error.';
            try {
                const err = await res.json();
                if (err && err.error) message = err.error;
            } catch {}
            document.getElementById('loginError').textContent = message + ` (HTTP ${res.status})`;
            basicAuth = null;
        }
    } catch (err) {
        document.getElementById('loginError').textContent = 'Network error: ' + (err.message || err);
        basicAuth = null;
    }
};
