function createStudentCard(student, eventStudents) {
    const studentWrapper = document.createElement("div");
    studentWrapper.classList.add("student-item");
    studentWrapper.addEventListener("click", (e) => {
        openStudentInfoPage(student);
    });

    studentWrapper.innerHTML = `
        <div class="student-text">
            <div class="student-name">
                ${isBrsmMember(student)}
                ${student.lastName} ${student.firstName} ${student.middleName}
            </div>
            <div class="student-group-number">
                ${student.groupNumber}, ${student.studentFaculty}
            </div>
        </div>
        <div class="student-events-number">
            ${eventStudents.innerHTML}
        </div>
    `
    return studentWrapper;
}

function isBrsmMember(student){
    if(student.brsmMember){
        return `<pre><img src="../../assets/icons/BRSM_member.png" alt="BRSM Member" class="icon-check"> </pre>`
    }
    else{
        return "";
    }
}

function openStudentInfoPage(student) {
    window.location.href = `../secretary/student-info-page.html?id=${student.studentId}`;
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
