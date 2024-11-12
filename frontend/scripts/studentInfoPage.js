
let students = [];
let events = [];
let studentsEvents = [];
let student = {}

function addStudentInfo(student){
    const studentInfoWrapper = document.querySelector('.student-info');

    studentInfoWrapper.innerHTML = `
        <div class="student-info__image">
                <img src="../../assets/images/фото.JPG" alt="Student photo" class="student_image">
            </div>
            <div class="student-info__block">
                <div class="student-info__table_block">
                    <div class="student-info__table_row">
                        <div class="student-info__table_column main-column-td">Фамилия</div>
                        <div class="student-info__table_column">${student.last_name}</div>
                    </div>
                    <div class="student-info__table_row">
                        <div class="student-info__table_column main-column-td">Имя</div>
                        <div class="student-info__table_column">${student.first_name}</div>
                    </div>
                    <div class="student-info__table_row">
                        <div class="student-info__table_column main-column-td">Отчество</div>
                        <div class="student-info__table_column">${student.middle_name}</div>
                    </div>
                    <div class="student-info__table_row">
                        <div class="student-info__table_column main-column-td">Группа</div>
                        <div class="student-info__table_column">${student.group_number}</div>
                    </div>
                </div>
                <div class="student-events-number">
                    
                </div>
            </div>
    `;
}

function generateEventsCount(eventsCount){
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
            <div class="students__event-card__name">
                ${event.event_name}
            </div>
            <div class="students__event-card__info">
                <div class="students__event-card__info__table_row">
                    <div class="students__event-card__info__table_column main-column-td-event">Дата:</div>
                    <div class="students__event-card__info__table_column">${event.event_date}</div>
                </div>
                <div class="students__event-card__info__table_row">
                    <div class="students__event-card__info__table_column main-column-td-event">Время:</div>
                    <div class="students__event-card__info__table_column">${event.event_time}</div>
                </div>
                <div class="students__event-card__info__table_row">
                    <div class="students__event-card__info__table_column main-column-td-event">Место встречи:</div>
                    <div class="students__event-card__info__table_column">${event.event_place}</div>
                </div>
                <div class="students__event-card__info__table_row">
                    <div class="students__event-card__info__table_column main-column-td-event">Количество ОПТ:</div>
                    <div class="students__event-card__info__table_column">${event.opt_count}ч</div>
                </div>
                <div class="students__event-card__info__table_row">
                    <div class="students__event-card__info__table_column main-column-td-event">Ходатайство:</div>
                    <div class="students__event-card__info__table_column">${event.for_petition ? 'Для ходатайства' : 'Не для ходатайства'}</div>
                </div>
            </div>
        </div>
    `
    return eventWrapper;
}

document.addEventListener('DOMContentLoaded', function () {
    const urlParams = new URLSearchParams(window.location.search);
    const studentId = urlParams.get('id');

    const list = document.querySelector('.students__events-list');

    if(studentId) {
        fetch('../../data/students.json')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok ' + response.statusText);
                }
                return response.json();
            })
            .then(data => {
                students = data;
                student = students.find((student) => {
                    return student.student_id === +studentId;
                });
                if (student) {
                    addStudentInfo(student);
                    generateEventsCount(student.events_id.length);
                    fetch('../../data/events.json')
                        .then(response => {
                            if (!response.ok) {
                                throw new Error('Network response was not ok ' + response.statusText);
                            }
                            return response.json();
                        })
                        .then(data => {
                            events = data;
                            studentsEvents = getStudentsEvents(student, events);
                            const list = document.querySelector('.students__events-list');
                            if(list){
                                renderEventList(list, studentsEvents)
                            }

                        })
                        .catch(error => {
                            console.error('Ошибка загрузки файла:', error);
                        });


                }
                else {
                    console.error("Студент с данным ID не найден");
                }
            })
            .catch(error => {
                console.error('Ошибка загрузки файла:', error);
            });
    }

});

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

function getEventById(i, events){
    for(event of events){
        if (i === event.event_id) {
            return event;
        }
    }
}

