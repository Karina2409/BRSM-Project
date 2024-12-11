let events = [];
let student = {};
let pastEvents = [];

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
            if (data.role !== 'STUDENT') {
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
        const list = document.querySelector('.students__events-list');
        let studentId = localStorage.getItem("studentId");

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
                            fetch('http://localhost:8080/events/past', {
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
                                .then(data => {
                                    pastEvents = data;
                                    addStudentInfo(student);
                                    generateEventsCount(student.events.length);
                                    renderEventsList(list, events, pastEvents);
                                })
                                .catch(error => {
                                    console.error('Ошибка мероприятий:', error);
                                });
                            return student;
                        });
                } else {
                    throw new Error("Студент с данным ID не найден");
                }
            })
            .then(student => {


            })
            .catch(error => {
                console.error('Ошибка при загрузке:', error);
            });

    }
);

const editButton = document.querySelector('.edit-button');
editButton.addEventListener('click', (e) => {
    document.location.href="./edit-profile-page.html";
})

function addStudentInfo(student) {
    const studentInfoWrapper = document.querySelector('.student-info');
    const imageSrc = `data:image/jpeg;base64,${student.image}`;
    studentInfoWrapper.innerHTML = `
        <div class="student-info__image">
            <img src="${imageSrc}" alt="Student photo" class="student_image">
        </div>
        <div class="student-info__block">
            <div class="student-info__table_block">
                <div class="student-info__table_row">
                    <div class="student-info__table_column main-column-td">ФИО</div>
                    <div class="student-info__table_column">${isNull(student.lastName)} ${isNull(student.firstName)} ${isNull(student.middleName)}</div>
                </div>
                <div class="student-info__table_row">
                    <div class="student-info__table_column main-column-td">Группа</div>
                    <div class="student-info__table_column">${isNull(student.groupNumber)}</div>
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

function isNull(value) {
    if (value === null) {
        return 'Неизвестно';
    } else return value;
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

function renderEventsList(list, events, pastEvents) {
    list.innerHTML = '';

    events.forEach(event => {
        const card = createEventStudentCard(event, pastEvents, isEventAvailableF);
        card.addEventListener('click', (e) => {
            if(e.target.closest(".dark-blue-button")) {
                takePartInEvent(event.eventId);
            }
            else if(e.target.closest(".gray-blue-button")) {
                dontTakePartInEvent(event.eventId);
            }
        });
        list.append(card);
    })
}

function isEventAvailableF(event, pastEvents) {
    for (const event1 of pastEvents) {
        if (!(event1.eventId === event.eventId)) {
            return true;
        }
    }
    return false;
}