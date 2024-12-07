let exemptions = [];

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

document.addEventListener("DOMContentLoaded", function() {
    renderSearchComponent("Введите название мероприятия", filterExemptions);

    const list = document.querySelector('.exemptions-list');

    if(list) {
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

function filterExemptions(exemption) {}

let pageViewCards = 6;

function renderExemptionsList(list, exemptions){
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
}

function addExemptionsCard(){
    const list = document.querySelector('.exemptions-list');
    pageViewCards += 6;
    renderExemptionsList(list, exemptions);
}