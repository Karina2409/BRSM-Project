//TODO: Изменить текст в элементе, заменить его на значения, полученные с сервера

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