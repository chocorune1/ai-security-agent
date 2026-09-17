function showMessage(message) {
    const result = document.getElementById("result");
    result.innerHTML = message;
}

function renderUser(user) {
    document.querySelector("#profile").innerHTML =
        "<div>" + user.name + "</div>";
}
