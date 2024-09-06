// ##################################################
// document.addEventListener('DOMContentLoaded', function() {
//     const passwordInput = document.querySelector('#id_password1');
//     const confirmPasswordInput = document.querySelector('#id_password2');
//     const passwordMatchDisplay = document.querySelector('#passwordMatch'); // Div for displaying password match

//     function updateCriteria() {
//         const val = passwordInput.value;
//         document.querySelector('#minChars').classList.toggle('pass', val.length >= 8);
//         document.querySelector('#upperCase').classList.toggle('pass', /[A-Z]/.test(val));
//         document.querySelector('#lowerCase').classList.toggle('pass', /[a-z]/.test(val));
//         document.querySelector('#digit').classList.toggle('pass', /\d/.test(val));
//         checkPasswordsMatch(); // Ensure this function is called here too, to update as the user types
//     }

//     function checkPasswordsMatch() {
//         const match = passwordInput.value === confirmPasswordInput.value;
//         passwordMatchDisplay.classList.toggle('pass', match && passwordInput.value.length > 0); // Ensure it turns green only if there is some input
//     }

//     passwordInput.addEventListener('input', updateCriteria);
//     confirmPasswordInput.addEventListener('input', checkPasswordsMatch);
// });
document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.querySelector('#id_password1');
    const confirmPasswordInput = document.querySelector('#id_password2');
    const passwordMatchDisplay = document.querySelector('#password_match'); // Select the <li> for password match

    function updateCriteria() {
        const val = passwordInput.value;
        document.querySelector('#minChars').classList.toggle('pass', val.length >= 10);
        document.querySelector('#upperCase').classList.toggle('pass', /[A-Z]/.test(val));
        document.querySelector('#lowerCase').classList.toggle('pass', /[a-z]/.test(val));
        document.querySelector('#digit').classList.toggle('pass', /\d/.test(val));
        document.querySelector('#symbol').classList.toggle('pass', /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]+/.test(val));
        checkPasswordsMatch(); // Ensure this function is called here too, to update as the user types
    }

    function checkPasswordsMatch() {
        const match = passwordInput.value === confirmPasswordInput.value && passwordInput.value.length > 0;
        passwordMatchDisplay.classList.toggle('pass', match); // Ensure it turns green only if there is some input and matches
    }

    passwordInput.addEventListener('input', updateCriteria);
    confirmPasswordInput.addEventListener('input', checkPasswordsMatch);
});
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

const csrftoken = getCookie('csrftoken');

function csrfSafeMethod(method) {
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}

$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        }
    }
});