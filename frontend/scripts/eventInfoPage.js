let students = [];
let events = [];
let event = {};

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

document.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const eventId = urlParams.get('id');

    const list = document.querySelector('.events__students-list');

    if (eventId) {
        const token = localStorage.getItem("authToken");
        fetch(`http://localhost:8080/events/${eventId}`, {
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
            .then(event => {
                if (event) {
                    return fetch(`http://localhost:8080/events/${eventId}/students`, {
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
                        .then(students => {
                            event.students = students;
                            event.studentsId = students.map(student => student.id);
                            return event;
                        });
                } else {
                    throw new Error("Мероприятие с данным ID не найдено");
                }
            })
            .then(event => {
                addEventInfo(event);
                renderStudentsList(list, event.students);
            })
            .catch(error => {
                console.error('Ошибка при загрузке:', error);
            });
    }
});

function addEventInfo(event) {
    const eventInfoWrapper = document.querySelector('.event-info');

    eventInfoWrapper.innerHTML = `
        <div class="event-info__image">
            <img src="../../assets/icons/brsm-icon.png" alt="BRSM icon" class="event_image">
        </div>
        <div class="event-info__block">
            <div class="event-info__table_block">
                <div class="event-info__table_row">
                    <div class="event-info__table_column event__main-column-td">Название</div>
                    <div class="event-info__table_column">${event.eventName}</div>
                </div>
                <div class="event-info__table_row">
                    <div class="event-info__table_column event__main-column-td">Дата</div>
                    <div class="event-info__table_column">${event.eventDate}</div>
                </div>
                <div class="event-info__table_row">
                    <div class="event-info__table_column event__main-column-td">Время</div>
                    <div class="event-info__table_column">${event.eventTime}</div>
                </div>
                <div class="event-info__table_row">
                    <div class="event-info__table_column event__main-column-td">Место</div>
                    <div class="event-info__table_column">${event.eventPlace}</div>
                </div>
                <div class="event-info__table_row">
                    <div class="event-info__table_column event__main-column-td">Количество ОПТ</div>
                    <div class="event-info__table_column">${event.optCount}ч</div>
                </div>
                <div class="event-info__table_row">
                    <div class="event-info__table_column event__main-column-td">Для ходатайства</div>
                    <div class="event-info__table_column">${event.forPetition? 'Да' : 'Нет'}</div>
                </div>
            </div>
        </div>
    `
}

function renderStudentsList(list, students) {
    list.innerHTML = '';

    students.forEach(student => {
        const eventStudents = generateEventsCount(student.eventCount);
        const card = createStudentCard(student, eventStudents);
        list.append(card);
    })
}