function createEventCard (event){
    const eventWrapper = document.createElement("div");
    eventWrapper.classList.add("event-card");

    eventWrapper.addEventListener('click', (e) => {
        openEventInfoPage(event);
    });

    eventWrapper.innerHTML = `
        <div class="event-card__image-container">
            <img src="../../assets/images/vozlozhenie%201.png" alt="Event Image" class="event-card__img">
        </div>
        <div class="event-card__info">
            <h2 class="event-card__title">${event.event_name}</h2>
            <div class="event-card__event-info">
                <div class="event-card__event-info__row">
                    <p class="event-card__event-info__row-title">Дата:</p>
                    <p class="event-card__event-info__row-text">${event.event_date}</p>
                </div>

                <div class="event-card__event-info__row">
                    <p class="event-card__event-info__row-title">Время:</p>
                    <p class="event-card__event-info__row-text">${event.event_time}</p>
                </div>

                <div class="event-card__event-info__row">
                    <p class="event-card__event-info__row-title">Место встречи: </p>
                    <p class="event-card__event-info__row-text">${event.event_place}</p>
                </div>

                <div class="event-card__event-info__row">
                    <p class="event-card__event-info__row-title">Количество ОПТ:</p>
                    <p class="event-card__event-info__row-text">${event.opt_count}ч</p>
                </div>

                <div class="event-card__event-info__row">
                    <p class="event-card__event-info__row-title">Ходатайство:</p>
                    <p class="event-card__event-info__row-text">${event.for_petition ? 'Для ходатайства' : 'Не для ходатайства'}</p>
                </div>
            </div>
        </div>

        <button class="dark-blue-button">Изменить</button>
    `;

    return eventWrapper;
}

function createEventNameComponent (event){
    const eventWrapper = document.createElement("div");
    eventWrapper.classList.add("event-name-card");
    eventWrapper.innerHTML = `${event.event_name}`
    return eventWrapper;
}

function openEventInfoPage(event){}