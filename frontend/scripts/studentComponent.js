//TODO: Изменить текст в элементе, заменить его на значения, полученные с сервера

let students = [];

function createStudentCard(student) {
    const studentWrapper = document.createElement("div");
    studentWrapper.classList.add("student-item");

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
            <img src="../../assets/icons/brsm-icon.png" alt="BRSM icon" class="brsm-card"/>
            <img src="../../assets/icons/brsm-icon.png" alt="BRSM icon" class="brsm-card"/>
            <img src="../../assets/icons/brsm-icon.png" alt="BRSM icon" class="brsm-card"/>
            <img src="../../assets/icons/brsm-icon.png" alt="BRSM icon" class="brsm-card"/>
            <img src="../../assets/icons/brsm-icon.png" alt="BRSM icon" class="brsm-card"/>
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

    students.forEach(student => {
        const card = createStudentCard(student);
        list.append(card);
    })
}