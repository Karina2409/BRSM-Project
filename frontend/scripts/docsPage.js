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
    const controlsContainer = document.querySelector(".controls__container");

    controlsContainer.innerHTML = `
        <div class="controls">
            <div class="documentation__control dark-blue-button active" data-docs="exemptions">
                Освобождения
            </div>
            <div class="documentation__control gray-blue-button" data-docs="reports">
                Докладные
            </div>
            <div class="documentation__control gray-blue-button" data-docs="petitions">
                Ходатайства
            </div>
        </div>
        <hr class="controls__line">
    `;

    setActiveDocFromURL();

    document.querySelectorAll('.documentation__control').forEach(item => {
        item.addEventListener('click', () => {
            const page = item.getAttribute('data-docs');
            if (!item.classList.contains('active')) {
                navigateToDocPage(page);
            }
        });
    });
})

function setActiveDocFromURL() {
    const path = window.location.pathname;
    let activePage = 'exemptions';
    if (path.includes('reports')) activePage = 'reports';
    else if (path.includes('petitions')) activePage = 'petitions';

    document.querySelectorAll('.documentation__control').forEach(item => {
        if (item.getAttribute('data-docs') === activePage) {
            item.classList.add('active');
            item.classList.remove('gray-blue-button');
            item.classList.add('dark-blue-button');
        } else {
            item.classList.remove('active');
            item.classList.add('gray-blue-button');
            item.classList.remove('dark-blue-button');
        }
    });
}

function navigateToDocPage(page) {
    switch (page) {
        case 'exemptions':
            window.location.href = `./exemptions-page.html`;
            break;
        case 'reports':
            window.location.href = `./reports-page.html`;
            break;
        case 'petitions':
            window.location.href = `./petitions-page.html`;
            break;
        default:
            console.error('Неизвестная страница:', page);
    }
}