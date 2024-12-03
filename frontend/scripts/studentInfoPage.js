let students = [];
let events = [];
let studentsEvents = [];
let student = {};

(async function checkAccess() {
    const token = localStorage.getItem("authToken");
    if (!token) {

        console.log("Токен не найден, пауза перед редиректом на /index.html");

        window.location.href = "/index.html";
        return;
    }

    try {
        const response = await fetch('http://localhost:8080/brsm/auth/validate', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`,
            }
        });

        if (response.ok) {
            const data = await response.json();
            if (data.role !== 'SECRETARY' && data.role !== 'CHIEF_SECRETARY') {
                alert('Доступ запрещен роль не та');
                window.location.href = "/index.html";
            }
        } else {
            localStorage.removeItem('accessToken');
            console.log('response не ок')
            window.location.href = "/index.html";
        }
    } catch (error) {
        console.error('Ошибка', error);
        window.location.href = "/index.html";
    }
})();

document.addEventListener('DOMContentLoaded', function () {
        const urlParams = new URLSearchParams(window.location.search);
        const studentId = urlParams.get('id');

        const list = document.querySelector('.students__events-list');

        if (studentId) {
            const token = localStorage.getItem("authToken");
            fetch(`http://localhost:8080/students/${studentId}`, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`,
                }
            })
                .then(response => {
                    if (!response.ok) {
                        throw new Error('Network response was not ok ' + response.statusText);
                    }
                    return response.json();
                })
                .then(student => {
                    if (student) {
                        return fetch(`http://localhost:8080/students/${studentId}/events`, {
                            method: 'GET',
                            headers: {
                                'Content-Type': 'application/json',
                                'Authorization': `Bearer ${token}`,
                            }
                        })
                            .then(response => {
                                if (!response.ok) {
                                    throw new Error('Ошибка запроса: ' + response.statusText);
                                }
                                return response.json();
                            })
                            .then(events => {
                                student.events = events;
                                student.eventsId = events.map(event => event.id);
                                return student;
                            });
                    } else {
                        throw new Error("Студент с данным ID не найден");
                    }
                })
                .then(student => {
                    // Обновляем интерфейс
                    addStudentInfo(student);
                    generateEventsCount(student.events.length);
                    renderEventList(list, student.events);
                })
                .catch(error => {
                    console.error('Ошибка при загрузке:', error);
                });
        }
    }
);

function addStudentInfo(student) {
    const studentInfoWrapper = document.querySelector('.student-info');

    studentInfoWrapper.innerHTML = `
        <div class="student-info__image">
                <img src="../../assets/images/фото.JPG" alt="Student photo" class="student_image">
            </div>
            <div class="student-info__block">
                <div class="student-info__table_block">
                    <div class="student-info__table_row">
                        <div class="student-info__table_column main-column-td">ФИО</div>
                        <div class="student-info__table_column">${student.lastName} ${student.firstName} ${student.middleName}</div>
                    </div>
                    <div class="student-info__table_row">
                        <div class="student-info__table_column main-column-td">Группа</div>
                        <div class="student-info__table_column">${student.groupNumber}</div>
                    </div>
                    <div class="student-info__table_row">
                        <div class="student-info__table_column main-column-td">Телеграмм</div>
                        <div class="student-info__table_column">${isNull(student.telegram)}</div>
                    </div>
                    <div class="student-info__table_row">
                        <div class="student-info__table_column main-column-td">Номер телефона</div>
                        <div class="student-info__table_column">${isNull(student.phoneNumber)}</div>
                    </div>
                </div>
                <div class="student-events-number">
                    
                </div>
            </div>
    `;
}

function isNull(value){
    if(value === null){
        return 'Неизвестно';
    }
    else return value;
}

function generateEventsCount(eventsCount) {
    const studentEventCount = document.querySelector('.student-events-number');

    studentEventCount.innerHTML = '';

    for (let i = 0; i < 5; i++) {
        const eventImage = document.createElement('img');

        if (i < eventsCount) {
            eventImage.setAttribute('src', '../../assets/icons/brsm-icon.png');
            eventImage.setAttribute('alt', 'BRSM Image');
            eventImage.setAttribute('class', 'brsm-card');
        } else {
            eventImage.setAttribute('src', '../../assets/icons/brsm-icon-gray.png');
            eventImage.setAttribute('alt', 'Gray BRSM Image');
            eventImage.setAttribute('class', 'brsm-card');
        }

        studentEventCount.appendChild(eventImage);
    }

    return studentEventCount;
}

function createEventCard(event) {
    const eventWrapper = document.createElement("div");
    eventWrapper.classList.add("students__event-card");

    eventWrapper.innerHTML = `
        <img src="../../assets/images/vozlozhenie%201.png" alt="Event Image"
             class="students__event-card__image">
        <div class="students__event-card__text-block">
            <div class="students__event-card__name__container">
                <div class="students__event-card__name">
                    ${event.eventName}
                </div>
            </div>
            <div class="students__event-card__info">
                <div class="students__event-card__info__table_row">
                    <div class="students__event-card__info__table_column main-column-td-event">Дата:</div>
                    <div class="students__event-card__info__table_column">${event.eventDate}</div>
                </div>
                <div class="students__event-card__info__table_row">
                    <div class="students__event-card__info__table_column main-column-td-event">Время:</div>
                    <div class="students__event-card__info__table_column">${event.eventTime}</div>
                </div>
                <div class="students__event-card__info__table_row">
                    <div class="students__event-card__info__table_column main-column-td-event">Место встречи:</div>
                    <div class="students__event-card__info__table_column">${event.eventPlace}</div>
                </div>
                <div class="students__event-card__info__table_row">
                    <div class="students__event-card__info__table_column main-column-td-event">Количество ОПТ:</div>
                    <div class="students__event-card__info__table_column">${event.optCount}ч</div>
                </div>
                <div class="students__event-card__info__table_row">
                    <div class="students__event-card__info__table_column main-column-td-event">Ходатайство:</div>
                    <div class="students__event-card__info__table_column">${event.forPetition ? 'Для ходатайства' : 'Не для ходатайства'}</div>
                </div>
            </div>
        </div>
    `
    return eventWrapper;
}

function renderEventList(list, events) {
    list.innerHTML = '';

    events.forEach(event => {
        const card = createEventCard(event);
        list.append(card);
    })
}

function getStudentsEvents(student, events) {
    const eventIds = student.events_id;
    for (let i = 0; i < eventIds.length; i++) {
        studentsEvents[i] = getEventById(eventIds[i], events);
    }
    return studentsEvents;
}

function getEventById(i, events) {
    for (event of events) {
        if (i === event.event_id) {
            return event;
        }
    }
}

