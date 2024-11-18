function createPetitionComponent(petition) {
    const petitionWrapper = document.createElement('div');
    petitionWrapper.classList.add('petition-card');
    petitionWrapper.classList.add('document-card');

    petitionWrapper.innerHTML = `
        <div class="document-card__name">${petition.petition_name}</div>

        <div class="document-card__info">
            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Дата:</div>
                <div class="document-card__info__row__text">${petition.petition_date}</div>
            </div>

            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Факультет:</div>
                <div class="document-card__info__row__text">${petition.student_faculty}</div>
            </div>

            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Фамилия студента:</div>
                <div class="document-card__info__row__text">${petition.student_name}</div>
            </div>
        </div>

        <div class="document-card__buttons">
            <button class="dark-blue-button document-card__button">Скачать</button>
            <button class="empty-button document-card__button">Удалить</button>
        </div>
    `;

    return petitionWrapper;
}