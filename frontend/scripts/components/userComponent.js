function clickOption(selection) {

    const options = selection.parentElement.querySelectorAll('.select-option-user');

    options.forEach((option) => {
        option.classList.toggle('unvisible');
    });
}

function createUserCard(user) {
    const userWrapper = document.createElement("div");
    userWrapper.classList.add("user-card");

    if (user.role === 'CHIEF_SECRETARY') {
        userWrapper.innerHTML = `
            <div class="user-card__user-name">
                ${user.lastName} ${user.firstName} ${user.middleName}
            </div>
            <div class="select-user">
                <div class="select-user__text">
                    ${getRole(user)}
                </div>
            </div>
        `;
    }
    else{
        userWrapper.innerHTML = `
            <div class="user-card__user-name">
                ${user.lastName} ${user.firstName} ${user.middleName}
            </div>
            <div class="selection__wrapper">
                <div class="select-user">
                    <div class="select-user__text">
                        ${getRole(user)}
                    </div>
                    <img src="../../assets/icons/Vector%201.png" alt="Vector" class="select-user__icon">
                </div>
                <div class="select-option-user unvisible ${setSelectedUser(user.role, 'SECRETARY')}" id="secretary" onclick="changeRole(${user.id}, 'SECRETARY')">
                    <div class="select-user__text">
                        Секретарь
                    </div>
                </div>
                <div class="select-option-user select-option-user-2 unvisible ${setSelectedUser(user.role, 'STUDENT')}" id="student" onclick="changeRole(${user.id}, 'STUDENT')">
                    <div class="select-user__text">
                        Студент
                    </div>
                </div>
            </div>
        `
    }

    return userWrapper;
}

function getRole(user) {
    switch (user.role) {
        case 'SECRETARY':
            return 'Секретарь';
        case 'STUDENT':
            return 'Студент';
        case 'CHIEF_SECRETARY':
            return 'Секретарь БРСМ';
        default:
            return 'Неизвестная роль';
    }
}

function setSelectedUser(userRole, currentRole) {
    return currentRole === userRole ? 'select' : '';
}
const token = localStorage.getItem("authToken");
async function changeRole(userId, newRole) {
    const payload = { role: newRole };

    try {
        const response = await fetch(`http://localhost:8080/users/${userId}/role`, {
            method: 'PATCH',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify(payload),
        });

        if (response.ok) {
            alert('Роль успешно изменена!');
            location.reload();
        } else {
            alert('Ошибка при изменении роли!');
        }
    } catch (error) {
        console.error('Ошибка при отправке запроса:', error);
        alert('Ошибка подключения к серверу.');
    }
}