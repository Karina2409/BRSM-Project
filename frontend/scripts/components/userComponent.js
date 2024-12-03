function clickOption(selection) {

    const options = selection.parentElement.querySelectorAll('.select-option-user');

    options.forEach((option) => {
        option.classList.toggle('unvisible');
    });
}

function createUserCard(user) {
    const userWrapper = document.createElement("div");
    userWrapper.classList.add("user-card");

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

            <div class="select-option-user unvisible ${setSelectedUser(user.role, 'SECRETARY')}" id="secretary">
                <div class="select-user__text">
                    Секретарь
                </div>
            </div>

            <div class="select-option-user select-option-user-2 unvisible ${setSelectedUser(user.role, 'STUDENT')}" id="student">
                <div class="select-user__text">
                    Студент
                </div>
            </div>
        </div>
    `
    return userWrapper;
}

function getRole(user) {
    switch (user.role) {
        case 'SECRETARY':
            return 'Секретарь';
        case 'STUDENT':
            return 'Студент';
        case 'CHIEF_SECRETARY':
            return 'Секретарь БРСМ'
    }
}

function setSelectedUser(userRole, currentRole) {
    if(currentRole === userRole){
        return 'select';
    }
}