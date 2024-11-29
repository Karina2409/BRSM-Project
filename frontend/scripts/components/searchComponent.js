function createSearchComponent(placeholderText){
    const searchWrapper = document.createElement('div');
    searchWrapper.classList.add('search-wrapper');
    console.log(placeholderText);

    searchWrapper.innerHTML = `
        <input type="text" class="search-input" placeholder="${placeholderText}">
        <button class="search-button" type="submit">
            <img src="../../assets/icons/search.svg" alt="Search" class="search-img">
            Искать
        </button>
    `;

    const searchInput = searchWrapper.querySelector('.search-input');
    const searchButton = searchWrapper.querySelector('.search-button');

    const performSearch = () => {
        const query = searchInput.value.trim().toLowerCase();
        filterStudents(query);
    };

    searchButton.addEventListener('click', performSearch);

    searchInput.addEventListener('keydown', (event) => {
        if (event.key === 'Enter') {
            performSearch();
        }
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