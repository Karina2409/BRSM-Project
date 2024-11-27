let students = [];

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
            console.log(data);
            if (data.role !== 'SECRETARY') {
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

document.addEventListener('DOMContentLoaded', function () {
    renderSearchComponent("Введите фамилию студента");
    const list = document.querySelector('.students-list');
    if (list) {
        const token = localStorage.getItem("authToken");
        fetch('http://localhost:8080/students/get-all', {
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
                renderStudentList(list, students);
            })
            .catch(error => {
                console.error('Ошибка студентов:', error);
            });

    }
})

function renderStudentList(list, students) {
    list.innerHTML = '';
    const button = document.querySelector('.show-more');
    if (students.length > 13) {
        button.classList.add('visible');
    }
    let i = 1;

    while (i <= 13) {
        students.forEach(student => {
            if (i <= 13) {
                console.log(student.eventCount);
                const eventStudents = generateEventsCount(student.eventCount);
                const card = createStudentCard(student, eventStudents);
                list.append(card);
                i++;
            }
        })
    }
}


function addStudentsCard() {
    const list = document.querySelector('.students-list');

    const button = document.querySelector('.show-more');
    button.classList.remove('visible');

    let i = 1;
    students.forEach(student => {
        if (i > 13) {
            const eventStudents = generateEventsCount(student.eventCount);
            const card = createStudentCard(student, eventStudents);
            list.append(card);
        }
        i++;
    })

}