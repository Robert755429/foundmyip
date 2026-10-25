function changeTheme(theme) {
    document.body.className = '';
    if(theme && theme !== 'cyber') document.body.classList.add('theme-' + theme);
    localStorage.setItem('selected_theme', theme);
}

function acceptCookies() {
    localStorage.setItem('cookies_accepted', 'true');
    document.getElementById('cookie-overlay').style.display = 'none';
}

function openModal(id) { document.getElementById(id).style.display = 'flex'; }
function closeModal(id) { document.getElementById(id).style.display = 'none'; }

window.onload = function() {
    const savedTheme = localStorage.getItem('selected_theme');
    if(savedTheme) {
        const selectEl = document.getElementById('themeSelect');
        if(selectEl) selectEl.value = savedTheme;
        changeTheme(savedTheme);
    }
    if(!localStorage.getItem('cookies_accepted')) {
        const cookieOverlay = document.getElementById('cookie-overlay');
        if(cookieOverlay) cookieOverlay.style.display = 'flex';
    }
}
