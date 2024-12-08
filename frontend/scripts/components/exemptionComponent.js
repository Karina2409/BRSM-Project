function createExemptionCard(exemption) {
    const exemptionWrapper = document.createElement("div");
    exemptionWrapper.classList.add("exemption-card");
    exemptionWrapper.classList.add('document-card');

    exemptionWrapper.innerHTML = `
        <div class="document-card__name">${exemption.exemptionName}</div>
        <div class="document-card__info">
            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Дата:</div>
                <div class="document-card__info__row__text">${formatDate(exemption.exemptionDate)}</div>
            </div>

            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Факультет:</div>
                <div class="document-card__info__row__text">${exemption.studentsFacultyExemption}</div>
            </div>

            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Мероприятие: </div>
                <div class="document-card__info__row__text">${exemption.eventName}</div>
            </div>
        </div>

        <div class="document-card__buttons">
            <button class="dark-blue-button document-card__button download-button" data-id="${exemption.exemptionId}">Скачать</button>
            <button class="empty-button document-card__button delete-button" data-id="${exemption.exemptionId}">Удалить</button>
        </div>
    `;

    return exemptionWrapper;
}

