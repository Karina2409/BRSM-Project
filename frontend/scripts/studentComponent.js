//TODO: Изменить текст в элементе, заменить его на значения, полученные с сервера

let students = [];

function createStudentCard(student, eventStudents) {
    const studentWrapper = document.createElement("div");
    studentWrapper.classList.add("student-item");
    studentWrapper.addEventListener("click", (e) => {
        openStudentInfoPage(student);
    });

    studentWrapper.innerHTML = `
        <div class="student-text">
            <div class="student-name">
                ${student.last_name} ${student.first_name} ${student.middle_name}
            </div>
            <div class="student-group-number">
                ${student.group_number}
            </div>
        </div>
        <div class="student-events-number">
        ${eventStudents.innerHTML}
        </div>
    `
    return studentWrapper;
}

document.addEventListener('DOMContentLoaded', function () {
    const list = document.querySelector('.students-list');
    if (list) {
        fetch('../../data/students.json')
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok ' + response.statusText);
                }
                return response.json();
            })
            .then(data => {
                students = data;
                renderStudentList(list, students);
            })
            .catch(error => {
                console.error('Ошибка загрузки файла:', error);
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
                const eventStudents = generateEventsCount(student.events_id.length);
                const card = createStudentCard(student, eventStudents);
                list.append(card);
                i++;
            }

        })
    }
}

function openStudentInfoPage(student) {
    window.location.href = `../secretary/student-info-page.html?id=${student.student_id}`;
}

function generateEventsCount(eventsCount) {
    const studentEventCount = document.createElement('div');
    studentEventCount.classList.add('student-events-number');

    studentEventCount.innerHTML = '';

    for (let i = 0; i < 5; i++) {
        const eventImage = document.createElement('img');

        if (i < eventsCount) {
            eventImage.setAttribute('src', '../../assets/icons/brsm-icon.png');
            eventImage.setAttribute('alt', 'BRSM Image');
            eventImage.setAttribute('class', 'brsm-card');
        } else {
            eventImage.setAttribute('src', '../../assets/icons/brsm-icon-gray.png');
            eventImage.setAttribute('alt', 'Gray BRSM Image');
            eventImage.setAttribute('class', 'brsm-card');
        }

        studentEventCount.appendChild(eventImage);
    }

    return studentEventCount;
}

function addStudentsCard() {
    const list = document.querySelector('.students-list');

    const button = document.querySelector('.show-more');
    button.classList.remove('visible');

    let i = 1;
    students.forEach(student => {
        if (i > 13) {
            const eventStudents = generateEventsCount(student.events_id.length);
            const card = createStudentCard(student, eventStudents);
            list.append(card);
        }
        i++;
    })

}