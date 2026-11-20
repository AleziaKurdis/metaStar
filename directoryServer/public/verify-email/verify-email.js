(() => {
    'use strict';
    const params = new URLSearchParams(window.location.search);
    const success = params.get('status') === 'success';
    const message = document.getElementById('verification-message');
    if (success) {
        message.textContent = 'Your email address has been verified. You can now sign in.';
        message.classList.add('success');
    } else {
        message.textContent = 'This verification link is invalid or has expired. If you still need help, contact the server administrator.';
        message.classList.add('error');
    }
})();
