let students = [];

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