function createSearchComponent(){
    const searchWrapper = document.createElement('div');
    searchWrapper.classList.add('search-wrapper');

    searchWrapper.innerHTML = `
        <input type="text" class="search-input" placeholder="Введите фамилию студента">
        <button class="search-button">
            <img src="../../assets/icons/search.svg" alt="Search" class="search-img">
            Искать
        </button>
    `;

    const searchButton = searchWrapper.querySelector('.search-button');
    searchButton.addEventListener('click', () => {
        const query = searchWrapper.querySelector('.search-input').value;
        console.log(`Searching for: ${query}`);
    });

    return searchWrapper;
}

function renderSearchComponent() {
    const targetElement = document.querySelector('#search');
    if (targetElement) {
        targetElement.appendChild(createSearchComponent());
    } else {
        console.error(`Target element "search" not found`);
    }
}