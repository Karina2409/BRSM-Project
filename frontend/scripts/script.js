document.addEventListener('DOMContentLoaded', () => {
    const header = document.querySelector('header');
    const footer = document.querySelector('footer');
    const arrow = document.querySelector('.arrow');

    if (arrow) {
        arrow.addEventListener('click', goBack);
    }

    // HTML для хедера с data-page для удобства обработки
    header.innerHTML = `
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
            </ul>
        </nav>
    `;

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
    else if (path.includes('documentations')) activePage = 'documentation';
    else if (path.includes('statistics')) activePage = 'statistics';

    document.querySelectorAll('.header-list__item').forEach(item => {
        if (item.getAttribute('data-page') === activePage) {
            item.classList.add('active');
        } else {
            item.classList.remove('active');
        }
    });
}

function navigateToPage(page) {
    switch (page) {
        case 'students':
            window.location.href = `../secretary/students-page.html`;
            break;
        case 'users':
            window.location.href = `../secretary/users-page.html`;
            break;
        case 'events':
            window.location.href = `../secretary/events-page.html`;
            break;
        case 'documentation':
            window.location.href = `../secretary/documentations-page.html`;
            break;
        case 'statistics':
            window.location.href = `../secretary/statistics-page.html`;
            break;
        default:
            console.error('Неизвестная страница:', page);
    }
}

function goBack() {
    window.history.back();
}