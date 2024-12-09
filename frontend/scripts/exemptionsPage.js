let exemptions = [];
let pastEvents = [];
let students = [];

const addButton = document.querySelector('.create-exemption');
const chooseEventModal = document.querySelector('.modal__choose_event');
const chooseStudentsModal = document.querySelector('.modal__choose_students');
const searchField = document.querySelector('.search-event');
const eventsList = document.querySelector('.choose_modal__events-list');

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
    renderSearchComponent("Введите название мероприятия", filterExemptions);

    const list = document.querySelector('.exemptions-list');

    if (list) {
        const token = localStorage.getItem("authToken");
        fetch('http://localhost:8080/exemptions/get-all', {
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
                exemptions = data;
                renderExemptionsList(list, exemptions);
            })
            .catch(error => {
                console.error('Ошибка мероприятий:', error);
            })
    }
})

function filterExemptions(query) {
    const list = document.querySelector('.exemptions-list');

    if (!list) {
        return;
    }

    if (!query) {
        renderExemptionsList(list, exemptions);
        return;
    }

    const filteredExemptions = exemptions.filter(exemption => {
        return exemption.eventName.toLowerCase().startsWith(query);
    });

    renderExemptionsList(list, filteredExemptions);
}

let pageViewCards = 9;

function renderExemptionsList(list, exemptions) {
    list.innerHTML = '';
    const button = document.querySelector('.show-more');
    if (exemptions.length > pageViewCards) {
        button.classList.add('visible');
    } else {
        button.classList.remove('visible');
    }

    let cards = 1;

    while (cards <= pageViewCards && exemptions.length >= cards) {
        exemptions.forEach(exemption => {
            if (cards <= pageViewCards && !(cards > exemptions.length)) {
                const card = createExemptionCard(exemption);
                list.append(card);
                cards++;
            }
        })
    }

    const deleteButtons = document.querySelectorAll('.delete-button');
    const downloadButtons = document.querySelectorAll('.download-button');

    deleteButtons.forEach((button) => {
        button.addEventListener('click', async (e) => {
            const exemptionId = e.target.dataset.id;
            openDeleteModal(deleteExemption, exemptionId);
        })
    })

    downloadButtons.forEach((button) => {
        button.addEventListener('click', async (e) => {
            const exemptionId = e.target.dataset.id;
            await downloadExemption(exemptionId);
        })
    })

}

function addExemptionsCard() {
    const list = document.querySelector('.exemptions-list');
    pageViewCards += 6;
    renderExemptionsList(list, exemptions);
}

async function deleteExemption(exemptionId) {
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch(`http://localhost:8080/exemptions/delete/${exemptionId}`, {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
        });

        if (!response.ok) {
            throw new Error(`Ошибка сохранения: ${response.statusText}`);
        }
    } catch (error) {
        console.error('Ошибка при удалении освобождения:', error);
    }
    window.location.href = "./exemptions-page.html";
}

async function downloadExemption(exemptionId) {
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch(`http://localhost:8080/exemptions/download/${exemptionId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
        });
        if (!response.ok) {
            throw new Error(`Ошибка сохранения: ${response.statusText}`);
        }
    } catch (error) {
        console.error('Ошибка при удалении освобождения:', error);
    }
    alert("Освобождение сохранено в папку D:/BRSM project/документация/освобождения")
}

addButton.addEventListener('click', openCreateExemptionModal);

function openCreateExemptionModal() {
    chooseEventModal.classList.add('visible');
    chooseEventModal.classList.remove('invisible');

    chooseStudentsModal.classList.add('invisible');
    chooseStudentsModal.classList.remove('visible');

    const backArrow = document.querySelector('.back-to-docs-page');
    if(backArrow){
        backArrow.addEventListener('click', ()=>{
            closeSelectEventsModal();
            document.location.href="./exemptions-page.html";
        });
    }

    if (eventsList) {
        const token = localStorage.getItem("authToken");
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
                renderEventsListExemption(eventsList, pastEvents);
            })
            .catch(error => {
                console.error('Ошибка мероприятий:', error);
            })
    }
}

function renderEventsListExemption(list, events) {
    list.innerHTML = '';
    events.forEach(event => {
        const card = createEventMiniComponent(event);
        list.append(card);
    })
}

function openSelectStudentsModal(event) {

    const token = localStorage.getItem("authToken");
    fetch(`http://localhost:8080/events/${event.eventId}/students`, {
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
            students = data;
            chooseStudentsModal.append(createSelectStudentModal(event, students));
        })
        .catch(error => {
            console.error('Ошибка мероприятий:', error);
        })

    closeSelectEventsModal();

    chooseStudentsModal.classList.remove('invisible');
    chooseStudentsModal.classList.add('visible');

}

function closeSelectEventsModal(){
    chooseEventModal.classList.remove('visible');
    chooseEventModal.classList.add('invisible');
}


function createSelectStudentModal(event) {
    const selectStudentModal = document.createElement('div');
    selectStudentModal.classList.add('choose_modal');
    selectStudentModal.innerHTML = `
        <img src="../../assets/icons/arrow%201.png" alt="Arrow" class="arrow back-to-select-event"/>
        
        <div class="choose_modal__text-block__container choose_modal__text-block__container__students">
        <div class="mini__event-card mini__event-card__students">${event.eventName}</div>
            <div class="choose_modal__heading">Выберите студентов</div>

            <div class="choose_modal__list choose_modal__students-list">
                <div class="choose_modal__select-all custom-checkbox">
                    <input type="checkbox" id="select-all-checkbox" class="custom-checkbox__input"/>
                    <label for="select-all-checkbox" class="custom-checkbox__label select-all-checkbox">Выбрать всех</label>
                </div>
                ${students.map(student => `
                    <div class="choose_modal__student-item">
                        <input type="checkbox" id="student-${student.studentId}" class="student-checkbox custom-checkbox__input" />
                        <label for="student-${student.studentId}" class="custom-checkbox__label">
                            <div class="custom-checkbox__label__card">
                                <div>${student.lastName} ${student.firstName} ${student.middleName}</div>
                                <div class="student__group-number">${student.groupNumber}</div>
                            </div>
                        </label>
                    </div>
                `).join('')}
            </div>
            <button class="gray-blue-button choose_modal__submit-btn">Сформировать</button>
        </div>
    `;

    document.body.appendChild(selectStudentModal);

    const checkboxes = selectStudentModal.querySelectorAll('.student-checkbox');
    const selectAllCheckbox = selectStudentModal.querySelector('#select-all-checkbox');
    const submitButton = selectStudentModal.querySelector('.choose_modal__submit-btn');

    selectAllCheckbox.addEventListener('change', () => {
        checkboxes.forEach(checkbox => {
            checkbox.checked = selectAllCheckbox.checked;
        });
        updateSubmitButtonState();
    });

    checkboxes.forEach(checkbox => {
        checkbox.addEventListener('change', () => {
            updateSubmitButtonState();
            if (!checkbox.checked) {
                selectAllCheckbox.checked = false;
            }
            if (Array.from(checkboxes).every(cb => cb.checked)) {
                selectAllCheckbox.checked = true;
            }
        });
    });

    function updateSubmitButtonState() {
        if (!submitButton) {
            console.error('Ошибка: Кнопка submit не найдена.');
            return;
        }
        const isAnySelected = Array.from(checkboxes).some(checkbox => checkbox.checked);
        if (isAnySelected) {
            submitButton.classList.remove('gray-blue-button');
            submitButton.classList.add('dark-blue-button');
        }

    }

    const backToSelectEventArrow = document.querySelector('.back-to-select-event');
    if(backToSelectEventArrow) {
        backToSelectEventArrow.addEventListener('click', (event) => {
            openCreateExemptionModal();
            selectStudentModal.remove();
        });
    }

    return selectStudentModal;

}
