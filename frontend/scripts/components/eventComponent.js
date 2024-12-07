function createEventCard(event, pastEvents) {
    const eventWrapper = document.createElement("div");
    eventWrapper.classList.add("students__event-card");
    eventWrapper.classList.add("event-card");

    eventWrapper.addEventListener('click', (e) => {
        if(e.target.closest(".dark-blue-button")) {
            openEditEventPage(event);
        }
        else if(!e.target.closest(".gray-blue-button")) {
            openEventInfoPage(event);
        }
    });

    eventWrapper.innerHTML = `
        <div class="students__event-card__text-block">
            <div class="students__event-card__name__container">
                <div class="students__event-card__name">
                    ${event.eventName}
                </div>
            </div>
            <div class="event-card__event-info">
                <div class="students__event-card__info__table_row">
                    <p class="students__event-card__info__table_column main-column-td-event">Дата:</p>
                    <p class="students__event-card__info__table_column">${formatDate(event.eventDate)}</p>
                </div>

                <div class="students__event-card__info__table_row">
                    <p class="students__event-card__info__table_column main-column-td-event">Время:</p>
                    <p class="students__event-card__info__table_column">${event.eventTime}</p>
                </div>

                <div class="students__event-card__info__table_row">
                    <p class="students__event-card__info__table_column main-column-td-event">Место встречи: </p>
                    <p class="students__event-card__info__table_column">${event.eventPlace}</p>
                </div>

                <div class="students__event-card__info__table_row">
                    <p class="students__event-card__info__table_column main-column-td-event">Количество ОПТ:</p>
                    <p class="students__event-card__info__table_column">${event.optCount}ч</p>
                </div>

                <div class="event-card__event-info__row">
                    <p class="event-card__event-info__row-title">Ходатайство:</p>
                    <p class="event-card__event-info__row-text">${event.forPetition ? 'Для ходатайства' : 'Не для ходатайства'}</p>
                </div>
            </div>
        </div>

        <button class="${isEventDone(event, pastEvents)}">Изменить</button>
    `;

    return eventWrapper;
}

function openEventInfoPage(event) {
    window.location.href = `../events/event-info-page.html?id=${event.eventId}`;
}

function openEditEventPage(event){
    window.location.href = `../events/edit-event-page.html?id=${event.eventId}`;
}

function isEventDone(event, pastEvents){
    for (const event1 of pastEvents) {
        if(event1.eventId === event.eventId){
            return 'gray-blue-button';
        }
    }
    return 'dark-blue-button';
}