let reports = [];

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
    const list = document.querySelector('.reports-list');
    const dormNumberFilter = document.querySelector('.controls__filter');

    if (list) {
        const token = localStorage.getItem("authToken");
        fetch('http://localhost:8080/reports/get-all', {
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
                reports = data;
                renderReportsList(list, reports);
            })
            .catch(error => {
                console.error('Ошибка мероприятий:', error);
            })
    }

    if (dormNumberFilter) {
        dormNumberFilter.addEventListener('change', () => {
            const selectedDormNumber = dormNumberFilter.value;

            const filteredReports = selectedDormNumber === 'non-choose'
                ? reports
                : reports.filter(report => report.dormNumber === Number(selectedDormNumber));
            renderReportsList(list, filteredReports);
        })
    }
});

let pageViewCards = 9;

function renderReportsList(list, reports) {
    list.innerHTML = '';
    const button = document.querySelector('.show-more');
    if (reports.length > pageViewCards) {
        button.classList.add('visible');
    } else {
        button.classList.remove('visible');
    }

    let cards = 1;

    while (cards <= pageViewCards && reports.length >= cards) {
        reports.forEach(report => {
            if (cards <= pageViewCards && !(cards > reports.length)) {
                const card = createReportCard(report);
                list.append(card);
                cards++;
            }
        })
    }

    const deleteButtons = document.querySelectorAll('.delete-button');
    const downloadButtons = document.querySelectorAll('.download-button');

    deleteButtons.forEach((button) => {
        button.addEventListener('click', async (e) => {
            const reportId = e.target.dataset.id;
            openDeleteModal(deleteReport, reportId);
        })
    });

    downloadButtons.forEach((button) => {
        button.addEventListener('click', async (e) => {
            const reportId = e.target.dataset.id;
            await downloadReport(reportId);
        })
    });
}

async function deleteReport(reportId) {
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch(`http://localhost:8080/reports/delete/${reportId}`, {
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
        console.error('Ошибка при удалении докладной:', error);
    }
    window.location.href = "./reports-page.html";
}

async function downloadReport(reportId) {
    try {
        const token = localStorage.getItem('authToken');
        const response = await fetch(`http://localhost:8080/reports/download/${reportId}`, {
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
        console.error('Ошибка при скачивании докладной:', error);
    }
    alert("Докладная сохранена в папку D:/BRSM project/документация/докладные")
}

function addReportsCard() {
    const list = document.querySelector('.reports-list');
    pageViewCards += 6;
    renderReportsList(list, reports);
}

document.querySelector('.create-report').addEventListener('click', async () => {
    let isReportWasCreated = false;
    reports.forEach(report => {
        const date = new Date(report.reportDate);
        const currentDate = new Date();
        const timeDifference = currentDate - date;
        const daysDifference = timeDifference / (1000 * 60 * 60 * 24);
        if (daysDifference < 30) {
            isReportWasCreated = true;
        }
    });
    if (isReportWasCreated) {
        alert('Докладная уже была создана в течение последнего месяца!');
    }

    if (!isReportWasCreated) {
        try {
            const token = localStorage.getItem("authToken");
            const createResponse = await fetch(`http://localhost:8080/reports/post/month`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                    'Content-Type': 'application/json'
                }
            });

            if (!createResponse.ok) {
                throw new Error('Ошибка создания докладной: ' + createResponse.statusText);
            }
            alert('Докладная успешно создана!');
            window.location.reload();

        } catch (error) {
            console.error('Ошибка:', error);
            alert('Произошла ошибка. Попробуйте снова.');
        }
    }


})