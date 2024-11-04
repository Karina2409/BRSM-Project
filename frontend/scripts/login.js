document.getElementsByClassName("get-greeting").innerHTML = getGreeting();

function handleSignUpClick() {
    const container = document.getElementById("container");
    container.classList.add("right-panel-active");
}

function handleSignInClick() {
    const container = document.getElementById("container");
    container.classList.remove("right-panel-active");
}

function getGreeting() {
    const now = new Date();
    const hour = now.getHours();

    if (hour >= 5 && hour < 12) {
        return "Доброе утро";
    } else if (hour >= 12 && hour < 17) {
        return "Добрый день";
    } else if (hour >= 17 && hour < 22) {
        return "Добрый вечер";
    } else {
        return "Доброй ночи";
    }
}

