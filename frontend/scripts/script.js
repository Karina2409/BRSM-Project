document.addEventListener('DOMContentLoaded', () => {
    const header = document.querySelector('header');
    const footer = document.querySelector('footer');
    const arrow = document.querySelector('.arrow');

    const userRole = localStorage.getItem('userRole');

    if (!userRole) {
        console.error('Роль пользователя не определена');
        return;
    }

    const templates = {
        CHIEF_SECRETARY: `
            <div class="header_container">
                <nav class="header-items">
                    <ul class="header-list">
                        <li class="header-list__item active" data-page="students">
                            Студенты
                        </li>
                        <li class="header-list__item" data-page="users">
                            Пользователи
                        </li>
                        <li class="header-list__item" data-page="events">
                            Мероприятия
                        </li>
                        <li class="header-list__item" data-page="documentation">
                            Документация
                        </li>
                        <li class="header-list__item" data-page="statistics">
                            Статистика
                        </li>
                        <li class="header-list__item" data-page="exit">
                            Выход
                        </li>
                    </ul>
                </nav>
            </div>
        `,
        SECRETARY: `
            <div class="header_container">
                <nav class="header-items">
                    <ul class="header-list">
                        <li class="header-list__item active" data-page="students">
                            Студенты
                        </li>
                        <li class="header-list__item active" data-page="events">
                            Мероприятия
                        </li>
                        <li class="header-list__item" data-page="documentation">
                            Документация
                        </li>
                        <li class="header-list__item" data-page="statistics">
                            Статистика
                        </li>
                        <li class="header-list__item" data-page="exit">
                            Выход
                        </li>
                    </ul>
                </nav>
            </div>
        `,
        STUDENT: `
            <div class="header_container">
                <nav class="header-items">
                    <ul class="header-list">
                        <li class="header-list__item active" data-page="main">
                            Главная
                        </li>
                        <li class="header-list__item active" data-page="events-student">
                            Мероприятия
                        </li>
                        <li class="header-list__item" data-page="secretaries">
                            Секретари
                        </li>
                        <li class="header-list__item" data-page="profile">
                            Профиль
                        </li>
                        <li class="header-list__item" data-page="exit">
                            Выход
                        </li>
                    </ul>
                </nav>
            </div>
        `
    };

    if (arrow) {
        arrow.addEventListener('click', goBack);
    }

    header.innerHTML = templates[userRole] || '<p>Ошибка: неизвестная роль</p>';

    footer.innerHTML = `
        <div class="footer_container">
            <div class="left_block__info">
                <div class="phone_and_location">
                    <div class="footer_phone">
                        Для связи с нами: +375-(29)-543-76-54
                    </div>
                    <div class="footer_location">
                        Приходите: БГУИР 1 корпус 311 аудитория
                    </div>
                </div>
                <div class="brsm_teg">
                    @BRSM_BSUIR
                </div>
            </div>

            <div class="right_block__info">
                <div class="social-block">
                    <img src="../../assets/icons/telegram_icon_white.png" alt="Telegram Icon" class="social-icon">
                    <div class="social_text">Telegram</div>
                </div>
                <div class="social-block">
                    <img src="../../assets/icons/instagram_logo_icon_white.png" alt="Instagram Icon" class="social-icon">
                    <div class="social_text">Instagram</div>
                </div>
            </div>
        </div>
    `;

    setActivePageFromURL();

    document.querySelectorAll('.header-list__item').forEach(item => {
        item.addEventListener('click', () => {
            const page = item.getAttribute('data-page');
            if (!item.classList.contains('active')) {
                navigateToPage(page);
            }
        });
    });
});

function setActivePageFromURL() {
    const path = window.location.pathname;

    let activePage = 'students';
    if (path.includes('users')) activePage = 'users';
    else if (path.includes('events')) activePage = 'events';
    else if (path.includes('documentation')) activePage = 'documentation';
    else if (path.includes('statistics')) activePage = 'statistics';
    else if (path.includes('exit')) activePage = 'exit';
    else if (path.includes('main')) activePage = 'main';
    else if (path.includes('profile')) activePage = 'profile';

    document.querySelectorAll('.header-list__item').forEach(item => {
        if (item.getAttribute('data-page') === activePage) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
}

function navigateToPage(page) {
    const anchorMapping = {
        'events-student': 'events-block', // ID блока на странице main
        'secretaries': 'secretaries-block' // ID блока на странице main
    };

    if (page === 'exit') {
        logOut();
        return;
    }

    if (anchorMapping[page]) {
        // Если якорь привязан к странице main
        window.location.href = `../student/main-page.html#${anchorMapping[page]}`;
    } else {
        // Переход на стандартные страницы
        const pagePaths = {
            'students': '../students/students-page.html',
            'users': '../users/users-page.html',
            'events': '../events/events-page.html',
            'documentation': '../documentation/exemptions-page.html',
            'statistics': '../statistics/statistics-page.html',
            'main': '../student/main-page.html',
            'profile': '../student/profile-page.html'
        };

        if (pagePaths[page]) {
            window.location.href = pagePaths[page];
        } else {
            console.error('Неизвестная страница:', page);
        }
    }
}

function goBack() {
    window.history.back();
}

async function logOut() {
    const token = localStorage.getItem("authToken");
    try {
        const response = await fetch('http://localhost:8080/brsm/auth/logout', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
        });

        if (response.ok) {
            localStorage.setItem('authToken', null);
            window.location.href = '../../index.html';
        } else {
            alert('Ошибка авторизации')
        }
    } catch (error) {
        console.error('Ошибка: ', error);
        alert('Ошибка сети');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const modal = document.querySelector(".modal__yes_or_no");
    const closeModal = document.querySelector(".modal__close-button");
    const modalNo = document.querySelector(".controls__no");
    const modalYes = document.querySelector(".controls__yes");

    function openDeleteModal(deleteItem, itemId){
        modal.classList.add("visible");
        modal.classList.remove("invisible");
        document.body.style.overflow = 'hidden';

        modal.addEventListener('click', (e) => {
            if(e.target === modal) {
                closeDeleteModal()
            }
        })

        closeModal.addEventListener('click', closeDeleteModal);

        modalNo.addEventListener('click', closeDeleteModal);

        modalYes.addEventListener('click', () => {
            deleteItem(itemId);
        });
    }

    function closeDeleteModal() {
        document.body.style.overflow = '';
        document.body.style.paddingRight = `0px`;
        modal.classList.remove('visible');
        modal.classList.add('invisible');
    }

    window.openDeleteModal = openDeleteModal;
})


function formatDate(dateString) {
    const date = new Date(dateString);
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const year = date.getFullYear();
    return `${day}.${month}.${year}`;
}