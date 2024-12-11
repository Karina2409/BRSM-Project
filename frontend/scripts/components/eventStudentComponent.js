function createEventStudentCard(event, studentEvents) {
    const eventWrapper = document.createElement("div");
    eventWrapper.classList.add("students__event-card");
    eventWrapper.classList.add("event-card");

    let isEventAvailable = isEventAvailableF(event, studentEvents);

    eventWrapper.innerHTML = `
        <div class="students__event-card__text-block">
            <div class="students__event-card__name__container">
                <div class="students__event-card__name">
                    ${event.eventName}
                </div>
            </div>
            <div class="event-card__event-info">
                <div class="event-card__event-info__row">
                    <p class="event-card__event-info__row-title">Дата:</p>
                    <p class="students__event-card__info__table_column">${formatDate(event.eventDate)}</p>
                </div>

                <div class="event-card__event-info__row">
                    <p class="event-card__event-info__row-title">Время:</p>
                    <p class="students__event-card__info__table_column">${event.eventTime}</p>
                </div>

                <div class="event-card__event-info__row">
                    <p class="event-card__event-info__row-title">Место встречи: </p>
                    <p class="students__event-card__info__table_column">${event.eventPlace}</p>
                </div>

                <div class="event-card__event-info__row">
                    <p class="event-card__event-info__row-title">Количество ОПТ:</p>
                    <p class="students__event-card__info__table_column">${event.optCount}ч</p>
                </div>

                <div class="event-card__event-info__row">
                    <p class="event-card__event-info__row-title">Ходатайство:</p>
                    <p class="event-card__event-info__row-text">${event.forPetition ? 'Для ходатайства' : 'Не для ходатайства'}</p>
                </div>
            </div>
        </div>

        <button class="${isEventAvailable ? 'gray-blue-button' : 'dark-blue-button'}" data-event-id="${event.eventId}">${isEventAvailable ? 'Отписаться' : 'Записаться'}</button>
    `;

    return eventWrapper;
}

function isEventAvailableF(event, studentEvents){
    for (const event1 of studentEvents) {
        if(event1.eventId === event.eventId){
            return true;
        }
    }
    return false;
}

async function takePartInEvent(eventId){
    const studentId = localStorage.getItem("studentId");
    try {
        const token = localStorage.getItem("authToken");
        const response = await fetch(`http://localhost:8080/se/${studentId}/events/${eventId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
        });

        if (!response.ok) {
            throw new Error(`Ошибка запроса: ${response.statusText}`);
        }
        alert('Вы записаны на мероприятие!');
    } catch (error) {
        console.error('Ошибка при записи на мероприятие:', error);
        alert('Не удалось записаться на мероприятие.');
    }
    document.location.reload();
}

async function dontTakePartInEvent(eventId){
    const studentId = localStorage.getItem("studentId");
    try{
        const token = localStorage.getItem('authToken');
        const response = await fetch(`http://localhost:8080/se/remove/student/${studentId}/event/${eventId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
        });

        if (!response.ok) {
            throw new Error(`Ошибка сохранения: ${response.statusText}`);
        }
        const card = document.querySelector(`[data-event-id="${eventId}"]`);
        console.log(card);
        alert('Вы отменили участие в мероприятии!');
    }
    catch (error) {
        console.error('Ошибка при отмене участия в мероприятии:', error);
    }
    document.location.reload();
}