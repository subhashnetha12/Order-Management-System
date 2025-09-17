document.addEventListener("DOMContentLoaded", function () {
    let alertContainer = document.getElementById("alert-container");
    
    if (!alertContainer) return;

    let alerts = alertContainer.querySelectorAll(".alert");

    if (alerts.length === 0) return; // No alerts to show

    setTimeout(() => {
        alertContainer.style.top = "30px"; 
        alerts.forEach(alert => alert.classList.add("show"));

        setTimeout(() => {
            alerts.forEach(alert => alert.classList.add("hide"));

            setTimeout(() => {
                alertContainer.style.top = "-100px"; 
                alertContainer.innerHTML = ""; 
            }, 500);
        }, 3000);
    }, 500);
});