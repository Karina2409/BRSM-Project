function createSearchComponent(placeholderText){
    const searchWrapper = document.createElement('div');
    searchWrapper.classList.add('search-wrapper');
    console.log(placeholderText);

    searchWrapper.innerHTML = `
        <input type="text" class="search-input" placeholder="${placeholderText}">
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

function renderSearchComponent(placeholderText) {
    const targetElement = document.querySelector('#search');
    if (targetElement) {
        targetElement.appendChild(createSearchComponent(placeholderText));
    } else {
        console.error(`Target element "search" not found`);
    }
}