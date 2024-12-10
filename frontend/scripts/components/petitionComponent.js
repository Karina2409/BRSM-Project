function createPetitionCard(petition) {
    const petitionWrapper = document.createElement('div');
    petitionWrapper.classList.add('petition-card');
    petitionWrapper.classList.add('document-card');

    petitionWrapper.innerHTML = `
        <div class="document-card__name">${petition.petitionName}</div>

        <div class="document-card__info">
            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Дата:</div>
                <div class="document-card__info__row__text">${formatDate(petition.petitionDate)}</div>
            </div>

            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Факультет:</div>
                <div class="document-card__info__row__text">${petition.studentFaculty}</div>
            </div>

            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Фамилия студента:</div>
                <div class="document-card__info__row__text">${petition.studentLastName}</div>
            </div>
        </div>

        <div class="document-card__buttons">
            <button class="dark-blue-button document-card__button download-button" data-id="${petition.petitionId}">Скачать</button>
            <button class="empty-button document-card__button delete-button" data-id="${petition.petitionId}">Удалить</button>
        </div>
    `;

    return petitionWrapper;
}