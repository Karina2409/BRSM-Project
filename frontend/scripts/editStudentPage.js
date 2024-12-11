let student = {};

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
            if (data.role !== 'SECRETARY' && data.role !== 'STUDENT') {
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

document.addEventListener('DOMContentLoaded', () => {
    const saveButton = document.querySelector('.save-student-changes');
    const studentId = localStorage.getItem("studentId");

    if (studentId) {
        const token = localStorage.getItem("authToken");
        fetch(`http://localhost:8080/students/${studentId}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`,
            }
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok ' + response.statusText);
                }
                return response.json();
            })
            .then(data => {
                student = data;
                addStudentEditInfo(student);
            })
            .catch(error => {
                console.error('Ошибка при загрузке:', error);
            });
    }

    saveButton.addEventListener('click', async () => {
        const token = localStorage.getItem("authToken");

        const lastName = document.querySelector('input[name="lastName"]').value;
        const firstName = document.querySelector('input[name="firstName"]').value;
        const middleName = document.querySelector('input[name="middleName"]').value;
        const groupNumber = document.querySelector('input[name="groupNumber"]').value;
        const studentFaculty = document.querySelector('input[name="studentFaculty"]').value;
        const phoneNumber = document.querySelector('input[name="phoneNumber"]').value;
        const telegram = document.querySelector('input[name="telegram"]').value;
        const dormitoryResidence = document.querySelector('#dormitoryResidence').checked;
        const studentFullNameD = dormitoryResidence ? document.querySelector('input[name="studentFullNameD"]').value : null;
        const dormNumber = dormitoryResidence ? document.querySelector('input[name="dormNumber"]').value : null;
        const dormBlockNumber = dormitoryResidence ? document.querySelector('input[name="dormBlockNumber"]').value : null;

        if (!lastName || !firstName || !groupNumber || !studentFaculty || !phoneNumber || !telegram) {
            alert('Пожалуйста, заполните все обязательные поля: Фамилия, Имя, Группа, Факультет, Номер телефона, Телеграм.');
            return;
        }

        if (dormitoryResidence) {
            if (!studentFullNameD || !dormNumber || !dormBlockNumber) {
                alert('Пожалуйста, заполните все поля проживания в общежитии.');
                return;
            }
        }

        const imageFile = document.querySelector('#imageInput').files[0];
        let imageBase64 = student.image;

        if (imageFile) {
            const reader = new FileReader();
            reader.onload = async function (e) {
                imageBase64 = e.target.result.split(',')[1];
                await saveStudentData();
            };
            reader.readAsDataURL(imageFile);
        } else {
            await saveStudentData();
        }

        async function saveStudentData() {
            const studentData = {
                lastName,
                firstName,
                middleName,
                groupNumber,
                studentFaculty,
                phoneNumber,
                telegram,
                dormitoryResidence,
                studentFullNameD,
                dormNumber,
                dormBlockNumber,
                image: imageBase64
            };

            try {
                const response = await fetch(`http://localhost:8080/students/student/${studentId}`, {
                    method: 'PUT',
                    headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`,
                    },
                    body: JSON.stringify(studentData),
                });

                if (response.ok) {
                    window.location.href = './profile-page.html';
                } else {
                    alert('Ошибка при сохранении данных. Попробуйте снова.');
                }
            } catch (error) {
                console.error('Ошибка при отправке данных:', error);
                alert('Ошибка при сохранении данных. Попробуйте снова.');
            }
        }
    });

});

function addStudentEditInfo(student) {
    const studentInfoWrapper = document.querySelector('.edit-student__info');
    const imageSrc = `data:image/jpeg;base64,${student.image}`;
    studentInfoWrapper.innerHTML = `
        <div class="student-info__image">
            <img src="${imageSrc}" alt="BRSM icon" class="edit-student__photo" id="studentImage">
            <input type="file" id="imageInput" style="display: none;" accept="image/*">
        </div>
        <div class="edit-student__block">
            <div class="edit-student__form">
                <div class="edit-student__table_row">
                    <div class="edit-student__table_column student__main-column-td">Фамилия</div>
                    <div class="edit-student__table_column">
                        <input type="text" class="input edit-student__input" name="lastName" value="${student.lastName === null ? '' : student.lastName}">
                    </div>
                </div>
                <div class="edit-student__table_row">
                    <div class="edit-student__table_column student__main-column-td">Имя</div>
                    <div class="edit-student__table_column">
                        <input type="text" class="input edit-student__input" name="firstName" value="${student.firstName === null ? '' : student.firstName}">
                    </div>
                </div>
                <div class="edit-student__table_row">
                    <div class="edit-student__table_column student__main-column-td">Отчество</div>
                    <div class="edit-student__table_column">
                        <input type="text" class="input edit-student__input" name="middleName" value="${student.middleName === null ? '' : student.middleName}">
                    </div>
                </div>
                <div class="edit-student__table_row">
                    <div class="edit-student__table_column student__main-column-td">Группа</div>
                    <div class="edit-student__table_column">
                        <input type="text" class="input edit-student__input" name="groupNumber" value="${student.groupNumber === null ? '' : student.groupNumber}">
                    </div>
                </div>
                <div class="edit-student__table_row">
                    <div class="edit-student__table_column student__main-column-td">Факультет</div>
                    <div class="edit-student__table_column">
                        <input type="text" class="input edit-student__input" name="studentFaculty" value="${student.studentFaculty === null ? '' : student.studentFaculty}">
                    </div>
                </div>
                <div class="edit-student__table_row">
                    <div class="edit-student__table_column student__main-column-td">Номер телефона</div>
                    <div class="edit-student__table_column">
                        <input type="text" class="input edit-student__input" name="phoneNumber" value="${student.phoneNumber === null ? '' : student.phoneNumber}">
                    </div>
                </div>
                <div class="edit-student__table_row">
                    <div class="edit-student__table_column student__main-column-td">Телеграм</div>
                    <div class="edit-student__table_column">
                        <input type="text" class="input edit-student__input" name="telegram" value="${student.telegram === null ? '' : student.telegram}">
                    </div>
                </div>
                <div class="edit-student__table_row">
                    <div class="edit-student__table_column student__main-column-td">Проживание в общежитии</div>
                    <div class="custom-checkbox">
                        <input type="checkbox" id="dormitoryResidence" name="forPetition" class="custom-checkbox__input" ${student.dormitoryResidence ? 'checked' : ''}>
                        <label for="dormitoryResidence" class="custom-checkbox__label"></label>
                    </div>
                </div>
                <div id="dormitoryFields" class="dormitory-fields" style="display: ${student.dormitoryResidence ? 'flex' : 'none'};">
                    <div class="edit-student__table_row">
                        <div class="edit-student__table_column student__main-column-td">ФИО в Д.п.</div>
                        <div class="edit-student__table_column">
                            <input type="text" class="input edit-student__input" name="studentFullNameD" value="${student.studentFullNameD === null ? '' : student.studentFullNameD}">
                        </div>
                    </div>
                    <div class="edit-student__table_row">
                        <div class="edit-student__table_column student__main-column-td">Номер общежития</div>
                        <div class="edit-student__table_column">
                            <input type="text" class="input edit-student__input" name="dormNumber" value="${student.dormNumber === null ? '' : student.dormNumber}">
                        </div>
                    </div>
                    <div class="edit-student__table_row">
                        <div class="edit-student__table_column student__main-column-td">Номер блока</div>
                        <div class="edit-student__table_column">
                            <input type="text" class="input edit-student__input" name="dormBlockNumber" value="${student.dormBlockNumber === null ? '' : student.dormBlockNumber}">
                        </div>
                    </div>
                </div>
                
            </div>
        </div>
    `;

    const dormitoryCheckbox = document.querySelector('#dormitoryResidence');
    const dormitoryFields = document.querySelector('#dormitoryFields');

    dormitoryCheckbox.addEventListener('change', (e) => {
        if (e.target.checked) {
            dormitoryFields.style.display = 'flex';
        } else {
            dormitoryFields.style.display = 'none';
        }
    });

    const studentImage = document.querySelector('#studentImage');
    const imageInput = document.querySelector('#imageInput');

    studentImage.addEventListener('click', () => {
        imageInput.click();
    });

    imageInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                studentImage.src = e.target.result;
                console.log(file)
            };
            reader.readAsDataURL(file);
        }
    });
}