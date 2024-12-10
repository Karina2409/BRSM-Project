let petitions = [];

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

}

function deletePetition(){

}

function downloadPetition(petitionId){

}