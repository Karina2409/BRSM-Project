students = [];

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

document.addEventListener("DOMContentLoaded", () => {
    const dateInput = document.getElementById("eventDate");
    const today = new Date().toISOString().split("T")[0]; // Получаем текущую дату в формате YYYY-MM-DD
    dateInput.setAttribute("min", today);

    const numberInputs = document.querySelectorAll('input[type="number"]');
    numberInputs.forEach(input => {
        input.addEventListener("input", (e) => {
            if (e.target.value < 0) {
                e.target.value = 0;
            }
        });
    });
});

const saveButton = document.querySelector(".save-button");

saveButton.addEventListener("click", async () => {
    try {
        const token = localStorage.getItem('authToken');

        const eventName = document.querySelector('.create-event__input[name="eventName"]').value;
        const eventDate = new Date(document.querySelector('.create-event__input[name="eventDate"]').value).toISOString().split('T')[0];
        const eventTime = document.querySelector('.create-event__input[name="eventTime"]').value + ":00";
        const eventPlace = document.querySelector('.create-event__input[name="eventPlace"]').value;
        const studentCount = parseInt(document.querySelector('.create-event__input[name="studentCount"]').value, 10) || 0;
        const optCount = parseInt(document.querySelector('.create-event__input[name="optCount"]').value, 10) || 0;
        const forPetition = document.querySelector('.custom-checkbox__input[name="forPetition"]').checked;

        const createdEvent = {
            eventName,
            eventDate,
            eventTime,
            eventPlace,
            studentCount,
            optCount,
            forPetition,
            students
        };

        const response = await fetch(`http://localhost:8080/events/post`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify(createdEvent),
        });

        if (!response.ok) {
            throw new Error(`Ошибка сохранения: ${response.status} ${response.statusText}`);
        }

        const result = await response.json();
        console.log("Мероприятие создано:", result);

        window.location.href = "./events-page.html";
    } catch (error) {
        console.error('Ошибка при сохранении мероприятия:', error);
        alert("Не удалось создать мероприятие. Проверьте введённые данные.");
    }
});