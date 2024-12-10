function createReportCard(report) {
    const reportWrapper = document.createElement('div');
    reportWrapper.classList.add('report-card');
    reportWrapper.classList.add('document-card');

    reportWrapper.innerHTML = `
        <div class="document-card__name">${report.reportName}</div>

        <div class="document-card__info">
            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Дата:</div>
                <div class="document-card__info__row__text">${formatDate(report.reportDate)}</div>
            </div>

            <div class="document-card__info__row">
                <div class="document-card__info__row__title">Номер общежития:</div>
                <div class="document-card__info__row__text">${report.dormNumber}</div>
            </div>
        </div>

        <div class="document-card__buttons">
            <button class="dark-blue-button document-card__button download-button" data-id="${report.reportId}">Скачать</button>
            <button class="empty-button document-card__button delete-button" data-id="${report.reportId}">Удалить</button>
        </div>
    `;

    return reportWrapper;
}