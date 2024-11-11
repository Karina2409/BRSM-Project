document.addEventListener('DOMContentLoaded', () => {
    const header = document.querySelector('header');
    header.innerHTML = `
        <nav class="header-items">
        <ul class="header-list">
            <li class="header-list__item active">
                Студенты
            </li>
            <li class="header-list__item">
                Пользователи
            </li>
            <li class="header-list__item">
                Мероприятия
            </li>
            <li class="header-list__item">
                Документация
            </li>
            <li class="header-list__item">
                Статистика
            </li>
        </ul>
    </nav>
    `;
})