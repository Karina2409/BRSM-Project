//TODO: Изменить текст в элементе, заменить его на значения, полученные с сервера

function createStudentComponent() {
    const studentWrapper = document.createElement("div");
    studentWrapper.classList.add("student-item");

    studentWrapper.innerHTML = `
        <div class="student-text">
            <div class="student-name">
                
                Сердюк Карина Владимировна
            </div>
            <div class="student-group-number">
                214301
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

function renderStudentComponent() {
    const targetElement = document.querySelector('.students-list');
    if (targetElement) {
        targetElement.appendChild(createStudentComponent());
    } else {
        console.error(`Target element "students-list" not found`);
    }
}