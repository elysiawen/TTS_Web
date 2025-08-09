function createNotificationElement() {
    const notification = document.createElement('div');
    notification.id = 'notification';
    notification.className = 'notification';
    document.body.appendChild(notification);
}

let notificationTimeout;

function showNotification(message, type = 'success') {
    let notification = document.getElementById("notification");
    if (!notification) {
        createNotificationElement();
        notification = document.getElementById("notification");
    }
    
    // 清除之前的定时器
    if (notificationTimeout) {
        clearTimeout(notificationTimeout);
        notificationTimeout = null;
    }
    
    // 清除之前的动画和样式
    notification.classList.remove("show", "hide", "success", "error", "warning", "loading");
    void notification.offsetWidth; // 强制重绘

    notification.innerHTML = message;
    switch (type) {
        case 'error':
            notification.classList.add("error");
            break;
        case 'warning':
            notification.classList.add("warning");
            break;
        case 'loading':
            notification.classList.add("loading");
            break;
        default:
            notification.classList.add("success");
    }
    notification.classList.add("show");

    if (type !== 'loading') {
        const animationDuration = 300;
        notificationTimeout = setTimeout(() => {
            notification.classList.remove("show");
            notification.classList.add("hide");
            setTimeout(() => {
                notification.classList.remove("hide");
            }, animationDuration);
        }, 3000);
    }
}
