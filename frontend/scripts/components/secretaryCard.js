function createSecretaryCard(secretary) {
    const secretaryWrapper = document.createElement("div");
    secretaryWrapper.classList.add("secretary-card");

    const imageSrc = `data:image/jpeg;base64,${secretary.image}`;
    const telegramUsername = secretary.telegramUsername.substring(1);

    secretaryWrapper.innerHTML = `
        <div class="fio-and-photo">
            <img src="${imageSrc}" alt="Secretary Photo" class="secretary-image"/>
            <div class="secretary-info">
                <div class="secretary-name">${secretary.lastName} ${secretary.firstName} ${secretary.middleName}</div>
                <div class="secretary-dop-info">
                    <div class="secretary-faculty">Секретарь ПО ОО «БРСМ» ${secretary.secretaryFaculty}</div>
                    <div class="secretary-telegram">${secretary.telegramUsername}</div>
                </div>
            </div>
        </div>
        <a href="https://t.me/${telegramUsername}" target="_blank">
        <div class="dark-blue-button">
            Написать
        </div>
        </a>
    `;

    return secretaryWrapper;
}