let users = [];

(async function checkAccess() {
    const token = localStorage.getItem("authToken");
    if (!token) {

        console.log("Токен не найден, пауза перед редиректом на /index.html");

        window.location.href = "/index.html";
        return;
    }

    try {
        const response = await fetch('http://localhost:8080/brsm/auth/validate', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
            }
        });

        if (response.ok) {
            const data = await response.json();
            if (data.role !== 'CHIEF_SECRETARY') {
                alert('Доступ запрещен роль не та');
                window.location.href = "/index.html";
            }
        } else {
            localStorage.removeItem('accessToken');
            console.log('response не ок')
            window.location.href = "/index.html";
        }
    } catch (error) {
        console.error('Ошибка', error);
        window.location.href = "/index.html";
    }
})();

document.addEventListener('DOMContentLoaded', () => {
    renderSearchComponent("Введите фамилию пользователя", filterUsers);

    const list = document.querySelector('.users-list');

    if (list) {
        const token = localStorage.getItem("authToken");
        fetch('http://localhost:8080/users', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            }
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Ошибка запроса: ' + response.statusText);
                }
                return response.json();
            })
            .then(data => {
                users = data;
                renderUserList(list, users);
            })
            .catch(error => {
                console.error('Ошибка пользователей:', error);
            });
    }
});

let pageViewCards = 13;

function renderUserList(list, users) {
    list.innerHTML = '';
    const button = document.querySelector('.show-more');
    if (users.length > pageViewCards) {
        button.classList.add('visible');
    } else {
        button.classList.remove('visible');
    }
    let nullUsersCount = 0;

    users.forEach(user => {
        if (user.lastName == null && user.firstName == null && user.middleName == null) {
            nullUsersCount++;
        }
    })

    let cards = 1;
    while (cards <= pageViewCards && (users.length - nullUsersCount) >= cards) {
        users.forEach(user => {
            if (cards <= pageViewCards && !(cards > (users.length - nullUsersCount))) {
                if (user.lastName !== null && user.firstName !== null && user.middleName !== null) {
                    const card = createUserCard(user);
                    setSelectedUser(card);
                    list.append(card);
                    cards++;
                }
            }

        })
    }

    const selections = list.querySelectorAll('.select-user');
    selections.forEach(selection => {
        selection.addEventListener('click', (e) => {
            clickOption(e.currentTarget);
        });
    });
}

function addUsersCard() {
    const list = document.querySelector('.users-list');
    pageViewCards += 13;
    renderUserList(list, users);
}

function filterUsers(query) {
    const list = document.querySelector('.users-list');

    if (!list) return;

    if (!query) {
        renderUserList(list, users);
        return;
    }

    const filteredUsers = users.filter(user => {
        if (!(user.lastName == null || user.firstName == null ||
            user.middleName == null)) {
            return user.lastName.toLowerCase().includes(query);
        }

    });

    renderUserList(list, filteredUsers);
}