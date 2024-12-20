let events = [];
let pastEvents = [];

const createButton = document.querySelector('.create-event');

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

document.addEventListener("DOMContentLoaded", function () {
    renderSearchComponent("Введите название мероприятия", filterEvents);

    const list = document.querySelector('.events-list');

    if (list) {
        const token = localStorage.getItem("authToken");
        fetch('http://localhost:8080/events/get-all', {
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
                        renderEventsList(list, events, pastEvents);
                    })
                    .catch(error => {
                        console.error('Ошибка мероприятий:', error);
                    })

            })
            .catch(error => {
                console.error('Ошибка мероприятий:', error);
            })
    }
})

let pageViewCards = 6;

function renderEventsList(list, events, pastEvents) {
    list.innerHTML = '';
    const button = document.querySelector('.show-more');
    if (events.length > pageViewCards) {
        button.classList.add('visible');
    } else {
        button.classList.remove('visible');
    }

    let cards = 1;

    while (cards <= pageViewCards && events.length >= cards) {
        events.forEach(event => {
            if (cards <= pageViewCards && !(cards > events.length)) {
                const card = createEventCard(event, pastEvents);
                list.append(card);
                cards++;
            }
        })
    }
}

function addEventsCard() {
    const list = document.querySelector('.events-list');
    pageViewCards += 6;
    renderEventsList(list, events, pastEvents);
}

function filterEvents(query) {
    const list = document.querySelector('.events-list');

    if (!list) {
        return;
    }

    if (!query) {
        renderEventsList(list, events);
        return;
    }

    const filteredEvents = events.filter(event => {
        return event.eventName.toLowerCase().startsWith(query);
    });

    renderEventsList(list, filteredEvents);
}

createButton.addEventListener('click', () => {
    window.location.href = "./create-event-page.html";
});