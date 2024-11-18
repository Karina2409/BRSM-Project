document.addEventListener('DOMContentLoaded', () => {
    const selections = document.querySelectorAll('.select-user');

    for (const selection of selections) {
        selection.addEventListener('click', (e) => {
            clickOption(e.currentTarget);
        })
    }
})

function clickOption(selection){
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
            ${user.last_name} ${user.first_name} ${user.middle_name}
        </div>
        <div class="selection__wrapper">
            <div class="select-user">
                <div class="select-user__text">
                    ${user.role}
                </div>
                <img src="../../assets/icons/Vector%201.png" alt="Vector" class="select-user__icon">
            </div>

            <div class="select-option-user unvisible">
                <div class="select-user__text">
                    Секретарь
                </div>
            </div>

            <div class="select-option-user select-option-user-2 unvisible select">
                <div class="select-user__text">
                    Студент
                </div>
            </div>
        </div>
    `
    return userWrapper;
}