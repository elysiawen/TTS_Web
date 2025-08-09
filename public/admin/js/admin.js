/**
 * 动态加载侧边栏，并自动将当前页面的链接设置为激活状态
 */
async function loadSidebar() {
    const sidebarContainer = document.getElementById('sidebar-container');
    if (!sidebarContainer) {
        console.error('Sidebar container not found!');
        return;
    }

    try {
        const response = await fetch('/admin/_sidebar.html');
        if (!response.ok) throw new Error('Could not fetch sidebar.');

        const sidebarHtml = await response.text();
        sidebarContainer.innerHTML = sidebarHtml;

        const currentPagePath = window.location.pathname;

        // --- 核心改动：创建一个函数来“规范化”路径 ---
        // 这个函数会移除路径末尾的斜杠，除非路径本身就是 "/"
        const normalizePath = (path) => {
            if (path.length > 1 && path.endsWith('/')) {
                return path.slice(0, -1);
            }
            return path;
        };

        const normalizedCurrentPath = normalizePath(currentPagePath);

        const links = sidebarContainer.querySelectorAll('a');
        links.forEach(link => {
            const normalizedLinkPath = normalizePath(link.pathname);

            // 使用规范化后的路径进行比较
            if (normalizedLinkPath === normalizedCurrentPath) {
                link.classList.add('active');
            }
        });

    } catch (error) {
        console.error('Failed to load sidebar:', error);
        sidebarContainer.innerHTML = '<p style="color:red; padding:20px;">侧边栏加载失败。</p>';
    }
}