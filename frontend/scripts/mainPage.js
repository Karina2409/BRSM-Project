let events = [];
let studentEvents = [];
let secretaries = [];
let studentId = 0;

document.addEventListener('DOMContentLoaded', () => {
    const userId = localStorage.getItem('userId');

    const token = localStorage.getItem("authToken");
    fetch(`http://localhost:8080/users/student/${userId}`, {
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
            studentId = data.studentId;
            localStorage.setItem("studentId", studentId);
        })
        .catch(error => {
            console.error('Ошибка мероприятий:', error);
        })

    const listEvent = document.querySelector('.events-list');
    const listSecretaries = document.querySelector('.secretaries-list');

    if (listEvent) {
        const token = localStorage.getItem("authToken");
        fetch('http://localhost:8080/events/upcoming', {
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
                events = data;
                fetch(`http://localhost:8080/students/${studentId}/events`, {
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
                        studentEvents = data;
                        renderEventsList(listEvent, events, studentEvents);
                    })
                    .catch(error => {
                        console.error('Ошибка мероприятий:', error);
                    })
            })
            .catch(error => {
                console.error('Ошибка студентов:', error);
            })
    }

    if (listSecretaries) {
        const token = localStorage.getItem("authToken");
        fetch('http://localhost:8080/secretaries/get-all', {
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
                secretaries = data;
                renderSecretariesList(listSecretaries, secretaries);
            })
            .catch(error => {
                console.error('Ошибка мероприятий:', error);
            })
    }

})

let pageViewEventsCards = 3;

function renderEventsList(list, events, studentEvents) {
    list.innerHTML = '';
    const button = document.querySelector('.show-more-events');
    if (events.length > pageViewEventsCards) {
        button.classList.add('visible');
    } else {
        button.classList.remove('visible');
    }

    let cards = 1;

    while (cards <= pageViewEventsCards && events.length >= cards) {
        events.forEach(event => {
            if (cards <= pageViewEventsCards && !(cards > events.length)) {
                const card = createEventStudentCard(event, studentEvents);
                card.addEventListener('click', (e) => {
                    if(e.target.closest(".dark-blue-button")) {
                        takePartInEvent(event.eventId);
                    }
                    else if(e.target.closest(".gray-blue-button")) {
                        dontTakePartInEvent(event.eventId);
                    }
                });
                list.append(card);
                cards++;
            }
        })
    }
}

function addEventsCard() {
    const list = document.querySelector('.events-list');
    pageViewEventsCards = events.length;
    renderEventsList(list, events);
}

let pageViewSecretariesCards = 4;

function renderSecretariesList(list, secretaries) {
    list.innerHTML = '';
    const button = document.querySelector('.show-more-secretaries');
    if (secretaries.length > pageViewSecretariesCards) {
        button.classList.add('visible');
    } else {
        button.classList.remove('visible');
    }

    let cards = 1;

    while (cards <= pageViewSecretariesCards && secretaries.length >= cards) {
        secretaries.forEach(secretary => {
            if (cards <= pageViewSecretariesCards && !(cards > secretaries.length)) {
                const card = createSecretaryCard(secretary);
                list.append(card);
                cards++;
            }
        })
    }
}

function addSecretariesCard() {
    const list = document.querySelector('.secretaries-list');
    pageViewSecretariesCards = secretaries.length;
    renderSecretariesList(list, secretaries);
}