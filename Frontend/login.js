function login() {

    const username =
        document.getElementById("username").value;

    const password =
        document.getElementById("password").value;

    if (
        username === "admin" &&
        password === "admin123"
    ) {

        localStorage.setItem("loggedIn", "true");

        window.location.href = "index.html";

    }

    else {

        document.getElementById("loginMessage").innerHTML =
            "❌ Invalid Username or Password";

    }

}