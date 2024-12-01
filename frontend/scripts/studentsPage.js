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

document.addEventListener('DOMContentLoaded', function () {
    renderSearchComponent("Введите фамилию студента", filterStudents);
    const list = document.querySelector('.students-list');
    const facultyFilter = document.querySelector('.controls__filter');

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

    facultyFilter.addEventListener('change', function () {
        const selectedFaculty = facultyFilter.value;

        const filteredStudents = selectedFaculty === 'not-choosen'
            ? students
            : students.filter(student => student.studentFaculty === selectedFaculty);

        console.log(filteredStudents);
        renderStudentList(list, filteredStudents);
    });
});


let pageViewCards = 13;

function renderStudentList(list, students) {
    list.innerHTML = '';
    const button = document.querySelector('.show-more');
    if (students.length > pageViewCards) {
        button.classList.add('visible');
    } else {
        button.classList.remove('visible');
    }
    let nullStudentCount = 0;

    students.forEach(student => {
        if (student.lastName == null && student.firstName == null && student.middleName == null) {
            nullStudentCount++;
        }
    })

    let cards = 1;
    while (cards <= pageViewCards && (students.length - nullStudentCount) >= cards) {
        students.forEach(student => {
            if (cards <= pageViewCards && !(cards > (students.length - nullStudentCount))) {
                if (student.lastName !== null && student.firstName !== null && student.middleName !== null) {
                    const eventStudents = generateEventsCount(student.eventCount);
                    const card = createStudentCard(student, eventStudents);
                    list.append(card);
                    cards++;
                }
            }

        })
    }
}


function addStudentsCard() {
    const list = document.querySelector('.students-list');
    pageViewCards += 13;
    console.log(pageViewCards);
    renderStudentList(list, students);
}

function filterStudents(query) {
    const list = document.querySelector('.students-list');

    if (!list) return;

    if (!query) {
        renderStudentList(list, students);
        return;
    }

    const filteredStudents = students.filter(student => {
        if (!(student.lastName == null || student.firstName == null ||
            student.middleName == null)) {
            return student.lastName.toLowerCase().includes(query);
        }

    });

    renderStudentList(list, filteredStudents);
}
