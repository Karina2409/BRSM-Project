let students = [];
let events = [];
let event = {};

const saveButton = document.querySelector('.save-event-changes');
const deleteButton = document.querySelector('.delete-event');

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
            .then(data => {
                event = data;
                addEventEditInfo(event);
                renderStudentsList(list, event.students);
            })
            .catch(error => {
                console.error('Ошибка при загрузке:', error);
            });
    }

});

function addEventEditInfo(event) {
    const eventInfoWrapper = document.querySelector('.edit-event__info');

    eventInfoWrapper.innerHTML = `
        <div class="event-info__image">
            <img src="../../assets/icons/brsm-icon.png" alt="BRSM icon" class="edit-event__brsm-photo">
        </div>
        <div class="edit-event__block">
            <div class="edit-event__form">
                <div class="edit-event__table_row">
                    <div class="edit-event__table_column event__main-column-td">Название</div>
                    <div class="edit-event__table_column">
                        <input type="text" class="input edit-event__input" name="eventName" value="${event.eventName.replace(/"/g, '&quot;')}">
                    </div>
                </div>
                <div class="edit-event__table_row">
                    <div class="edit-event__table_column event__main-column-td">Дата</div>
                    <div class="edit-event__table_column">
                        <input type="text" class="input edit-event__input" name="eventDate" value="${event.eventDate}">
                    </div>
                </div>
                <div class="edit-event__table_row">
                    <div class="edit-event__table_column event__main-column-td">Время</div>
                    <div class="edit-event__table_column">
                        <input type="text" class="input edit-event__input" name="eventTime" value="${event.eventTime}">
                    </div>
                </div>
                <div class="edit-event__table_row">
                    <div class="edit-event__table_column event__main-column-td">Место</div>
                    <div class="edit-event__table_column">
                        <input type="text" class="input edit-event__input" name="eventPlace" value="${event.eventPlace.replace(/"/g, '&quot;')}">
                    </div>
                </div>
                <div class="edit-event__table_row">
                    <div class="edit-event__table_column event__main-column-td">Количество студентов</div>
                    <div class="edit-event__table_column">
                        <input type="text" class="input edit-event__input" name="studentCount" value="${event.studentCount}">
                    </div>
                </div>
                <div class="edit-event__table_row">
                    <div class="edit-event__table_column event__main-column-td">Количество ОПТ</div>
                    <div class="edit-event__table_column">
                        <input type="text" class="input edit-event__input" name="optCount" value="${event.optCount}">
                    </div>
                </div>
                <div class="edit-event__table_row">
                    <div class="edit-event__table_column event__main-column-td">Для ходатайства</div>
                    <div class="edit-event__table_column">
                        <input type="text" class="input edit-event__input" name="optCount" value="${event.optCount}">
                    </div>
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

saveButton.addEventListener('click', async () => {
    try {
        const token = localStorage.getItem('authToken');
        const urlParams = new URLSearchParams(window.location.search);
        const eventId = urlParams.get('id');

        const eventName = document.querySelector('.edit-event__input[value][name="eventName"]').value;
        const eventDate = new Date(document.querySelector('.edit-event__input[name="eventDate"]').value).toISOString().split('T')[0];
        const eventTime = document.querySelector('.edit-event__input[name="eventTime"]').value;
        const eventPlace = document.querySelector('.edit-event__input[value][name="eventPlace"]').value;
        const studentCount = document.querySelector('.edit-event__input[value][name="studentCount"]').value;
        const optCount = document.querySelector('.edit-event__input[value][name="optCount"]').value;

        const updatedEvent = {
            eventId,
            eventName,
            eventDate,
            eventTime,
            eventPlace,
            studentCount,
            optCount,
            forPetition: event.forPetition,
            students: students
        };

        const response = await fetch(`http://localhost:8080/events/event/update/${eventId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify(updatedEvent),
        });

        if (!response.ok) {
            throw new Error(`Ошибка сохранения: ${response.statusText}`);
        }
    } catch (error) {
        console.error('Ошибка при сохранении изменений:', error);
    }
    window.location.href = "./events-page.html";
});

deleteButton.addEventListener('click', async () => {

    openDeleteModal(deleteEvent);
})

async function deleteEvent() {
    try{
        const token = localStorage.getItem('authToken');
        const urlParams = new URLSearchParams(window.location.search);
        const eventId = urlParams.get('id');
        const response = await fetch(`http://localhost:8080/events/delete/${eventId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
        });

        if (!response.ok) {
            throw new Error(`Ошибка сохранения: ${response.statusText}`);
        }
    }
    catch (error) {
        console.error('Ошибка при удалении мероприятия:', error);
    }
    window.location.href = "./events-page.html";
    modal.addEventListener('click', closeDeleteModal)
}