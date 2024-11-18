function createReportComponent(report) {
    const reportWrapper = document.createElement('div');
    reportWrapper.classList.add('report-card');
    reportWrapper.classList.add('document-card');

    reportWrapper.innerHTML = `
        <div class="document-card__name">${report.report_name}</div>

        <div class="document-card__info">
            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Дата:</div>
                <div class="document-card__info__row__text">${report.report_date}</div>
            </div>

            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Номер общежития:</div>
                <div class="document-card__info__row__text">${report.dorm_number}</div>
            </div>
        </div>

        <div class="document-card__buttons">
            <button class="dark-blue-button document-card__button">Скачать</button>
            <button class="empty-button document-card__button">Удалить</button>
        </div>
    `;

    return reportWrapper;
}