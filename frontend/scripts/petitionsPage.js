let petitions = [];
let eligibleStudents = [];

const addButton = document.querySelector('.create-petition');
const chooseStudentModal = document.querySelector('.modal__choose_student');
const studentsList = document.querySelector('.choose_modal__students-list');

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
    renderSearchComponent("Введите фамилию студента", filterPetitions);

    const list = document.querySelector('.petitions-list');
    if (list) {
        const token = localStorage.getItem("authToken");
        fetch('http://localhost:8080/petitions/get-all', {
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
                petitions = data;
                renderPetitionsList(list, petitions);
            })
            .catch(error => {
                console.error('Ошибка ходатайств:', error);
            })
    }
})

let pageViewCards = 9;

function renderPetitionsList(list, petitions) {
    list.innerHTML = '';
    const button = document.querySelector('.show-more');
    if (petitions.length > pageViewCards) {
        button.classList.add('visible');
    } else {
        button.classList.remove('visible');
    }

    let cards = 1;

    while (cards <= pageViewCards && petitions.length >= cards) {
        petitions.forEach(petition => {
            if (cards <= pageViewCards && !(cards > petitions.length)) {
                const card = createPetitionCard(petition);
                list.append(card);
                cards++;
            }
        })
    }

    const deleteButtons = document.querySelectorAll('.delete-button');
    const downloadButtons = document.querySelectorAll('.download-button');

    deleteButtons.forEach((button) => {
        button.addEventListener('click', async (e) => {
            const petitionId = e.target.dataset.id;
            openDeleteModal(deletePetition, petitionId);
        })
    });

    downloadButtons.forEach((button) => {
        button.addEventListener('click', async (e) => {
            const petitionId = e.target.dataset.id;
            await downloadPetition(petitionId);
        })
    });
}

function addPetitionsCard(){
    const list = document.querySelector('.petitions-list');
    pageViewCards += 6;
    renderPetitionsList(list, petitions);
}

async function deletePetition(petitionId){
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch(`http://localhost:8080/petitions/delete/${petitionId}`, {
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
        console.error('Ошибка при удалении ходатайства:', error);
    }
    window.location.href = "./petitions-page.html";
}

async function downloadPetition(petitionId){
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch(`http://localhost:8080/petitions/download/${petitionId}`, {
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
        console.error('Ошибка при скачивании ходатайства:', error);
    }
    alert("Ходатайство сохранено в папку D:/BRSM project/документация/ходатайства")
}

function filterPetitions(query){
    const list = document.querySelector('.petitions-list');

    if (!list) {
        return;
    }

    if (!query) {
        renderPetitionsList(list, petitions);
        return;
    }

    const filteredPetitions = petitions.filter(petition => {
        return petition.studentLastName.toLowerCase().startsWith(query);
    });

    renderPetitionsList(list, filteredPetitions);
}

addButton.addEventListener('click', openSelectStudentsModal);

function openSelectStudentsModal() {
    chooseStudentModal.classList.add('visible');
    chooseStudentModal.classList.remove('invisible');

    const backArrow = document.querySelector('.back-to-docs-page');
    if(backArrow){
        backArrow.addEventListener('click', ()=>{
            closeSelectStudentModal();
            document.location.href="./petitions-page.html";
        });
    }

    if(studentsList){
        const token = localStorage.getItem("authToken");
        fetch('http://localhost:8080/petitions/eligible', {
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
                eligibleStudents = data;
                renderStudentsListExemption(studentsList, eligibleStudents);
            })
            .catch(error => {
                console.error('Ошибка мероприятий:', error);
            })
    }
}

function renderStudentsListExemption(list, eligibleStudents) {
    list.innerHTML = '';
    list.innerHTML = `
        ${eligibleStudents.map(student => `
            <div class="choose_modal__student-item" data-id="${student.studentId}">    
                <div>${student.lastName} ${student.firstName} ${student.middleName}</div>
                <div class="student__group-number">${student.groupNumber}</div>
            </div>
        `).join('')}
    `;

    const studentItems = document.querySelectorAll('.choose_modal__student-item');
    studentItems.forEach(studentItem => {
        studentItem.addEventListener('click', ()=>{
            const studentId = studentItem.dataset.id;
            createPetition(studentId);
        });
    })

}

async function createPetition(studentId) {
    try {
        const token = localStorage.getItem("authToken");
        const response = await fetch(`http://localhost:8080/petitions/post/${studentId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
        });

        if (!response.ok) {
            throw new Error(`Ошибка запроса: ${response.statusText}`);
        }

        alert('Ходатайство успешно создано!');
        closeSelectStudentModal();
        window.location.href = "./petitions-page.html";
    } catch (error) {
        console.error('Ошибка при создании освобождения:', error);
        alert('Не удалось создать освобождение.');
        closeSelectStudentModal();
    }
}



function closeSelectStudentModal(){
    chooseStudentModal.classList.remove('visible');
    chooseStudentModal.classList.add('invisible');
}

// const searchWrapper = document.querySelector('.search-wrapper');
// const searchInput = searchWrapper.querySelector('.search-input');
// const searchButton = searchWrapper.querySelector('.search-button');
//
// const performSearch = () => {
//     const query = searchInput.value.trim().toLowerCase();
//     filterPetitions(query);
// };
//
// searchButton.addEventListener('click', performSearch);
//
// searchInput.addEventListener('keydown', (event) => {
//     if (event.key === 'Enter') {
//         performSearch();
//     }
// });
//
