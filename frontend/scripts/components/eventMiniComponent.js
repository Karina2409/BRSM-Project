function createEventMiniComponent(event){
    const eventWrapper = document.createElement("div");
    eventWrapper.classList.add("mini__event-card");

    eventWrapper.innerHTML = `
        ${event.eventName}
    `;

    eventWrapper.addEventListener("click", () => {
        openSelectStudentsModal(event);
    })

    return eventWrapper;
}