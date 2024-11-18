function createExemptionComponent(exemption) {
    const exemptionWrapper = document.createElement("div");
    exemptionWrapper.classList.add("exemption-card");

    exemptionWrapper.innerHTML = `
        <div class="exemption-card__name">${exemption.exemption_name}</div>
        <div class="exemption-card__info">
            <div class="exemption-card__info__row">
                <div class="exemption-card__info__row__title">Дата:</div>
                <div class="exemption-card__info__row__text">${exemption.exemption_date}</div>
            </div>

            <div class="exemption-card__info__row">
                <div class="exemption-card__info__row__title">Факультет:</div>
                <div class="exemption-card__info__row__text">${exemption.students_faculty}</div>
            </div>

            <div class="exemption-card__info__row">
                <div class="exemption-card__info__row__title">Мероприятие: </div>
                <div class="exemption-card__info__row__text">${exemption.event_name}</div>
            </div>
        </div>

        <div class="exemption-card__buttons">
            <button class="dark-blue-button exemption-card__button">Скачать</button>
            <button class="empty-button exemption-card__button">Удалить</button>
        </div>
    `;

    return exemptionWrapper;
}