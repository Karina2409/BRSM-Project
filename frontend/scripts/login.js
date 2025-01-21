document.addEventListener('DOMContentLoaded', () => {
    const signInForm = document.getElementById('signInForm');
    if (signInForm) {
        const emailInput = signInForm.querySelector('input[type="email"]');
        const passwordInput = signInForm.querySelector('input[type="password"]');
        if (emailInput) emailInput.value = '';
        if (passwordInput) passwordInput.value = '';
    }

    const signUpForm = document.getElementById('signUpForm');
    if (signUpForm) {
        const emailInput = signUpForm.querySelector('#email');
        const passwordInput = signUpForm.querySelector('#password');
        if (emailInput) emailInput.value = '';
        if (passwordInput) passwordInput.value = '';
    }

    if(signInForm) {
        signInForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const email = e.target.querySelector('input[type="email"]').value;
            const password = e.target.querySelector('input[type="password"]').value;

            try{
                const response = await fetch('http://localhost:8080/brsm/auth/authenticate', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({email, password}),
                });

                if (response.ok) {
                    const data = await response.json();
                    localStorage.setItem('authToken', data.token);
                    localStorage.setItem('userRole', data.role);
                    localStorage.setItem('userId', data.id);

                    const userRole = data.role;
                    redirectUserByRole(userRole);
                } else {
                    alert('Ошибка авторизации')
                }
            } catch (error) {
                console.error('Ошибка: ', error);
                alert('Ошибка сети');
            }
        })
    }

    if(signUpForm) {
        signUpForm.addEventListener('submit', async (e) => {
            e.preventDefault();

            const email = e.target.querySelector('#email').value;
            const password = e.target.querySelector('#password').value;

            try {
                const response = await fetch('http://localhost:8080/brsm/auth/signUp', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({email, password}),
                });

                if (response.ok) {
                    alert('Регистрация прошла успешно. Теперь войдите в аккаунт.')
                } else {
                    alert('Ошибка регистрации');
                }
            } catch (error) {
                console.error('Ошибка: ', error);
                alert('Ошибка сети');
            }
        })
    }
})

function redirectUserByRole(role) {
    if (role === 'STUDENT') {
        window.location.href = '/pages/student/main-page.html';
    } else if (role === 'SECRETARY') {
        window.location.href = '../pages/students/students-page.html';
    } else if (role === 'CHIEF_SECRETARY') {
        window.location.href = '../pages/students/students-page.html';
    } else {
        alert('Неизвестная роль');
    }
}

document.getElementsByClassName("get-greeting").innerHTML = getGreeting();

function handleSignUpClick() {
    const container = document.getElementById("container");
    container.classList.add("right-panel-active");
}

function handleSignInClick() {
    const container = document.getElementById("container");
    container.classList.remove("right-panel-active");
}

function getGreeting() {
    const now = new Date();
    const hour = now.getHours();

    if (hour >= 5 && hour < 12) {
        return "Доброе утро";
    } else if (hour >= 12 && hour < 17) {
        return "Добрый день";
    } else if (hour >= 17 && hour < 22) {
        return "Добрый вечер";
    } else {
        return "Доброй ночи";
    }
}

