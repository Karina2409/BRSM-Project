document.addEventListener('DOMContentLoaded', () => {
    const header = document.querySelector('header');
    const footer = document.querySelector('footer');

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
                <div class="social_text">Telegram</div>
            </div>
        </div>
    </div>
    `
})