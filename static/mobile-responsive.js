document.addEventListener('DOMContentLoaded', function() {
    // 移动端侧边栏切换逻辑
    function setupMobileSidebar() {
        // 检查是否存在侧边栏
        const sidebar = document.querySelector('.sidebar, .admin-sidebar');
        const content = document.querySelector('.content, .admin-content');
        const navbar = document.querySelector('.navbar');
        
        if (sidebar && content && navbar) {
            // 创建菜单按钮
            const menuBtn = document.createElement('button');
            menuBtn.className = 'mobile-menu-btn';
            menuBtn.innerHTML = '<i class="fas fa-bars"></i>';
            menuBtn.style.position = 'fixed';
            menuBtn.style.top = '10px';
            menuBtn.style.left = '10px';
            menuBtn.style.zIndex = '2000';
            menuBtn.style.width = '40px';
            menuBtn.style.height = '40px';
            menuBtn.style.border = 'none';
            menuBtn.style.borderRadius = '50%';
            menuBtn.style.background = 'rgba(255, 255, 255, 0.9)';
            menuBtn.style.boxShadow = '0 2px 5px rgba(0,0,0,0.2)';
            menuBtn.style.display = 'none';
            menuBtn.style.justifyContent = 'center';
            menuBtn.style.alignItems = 'center';
            menuBtn.style.cursor = 'pointer';
            menuBtn.style.fontSize = '18px';
            
            // 添加到body
            document.body.appendChild(menuBtn);
            
            // 创建遮罩层
            const overlay = document.createElement('div');
            overlay.className = 'sidebar-overlay';
            overlay.style.position = 'fixed';
            overlay.style.top = '0';
            overlay.style.left = '0';
            overlay.style.width = '100%';
            overlay.style.height = '100%';
            overlay.style.backgroundColor = 'rgba(0,0,0,0.5)';
            overlay.style.zIndex = '1500';
            overlay.style.display = 'none';
            document.body.appendChild(overlay);
            
            // 切换侧边栏显示/隐藏
            menuBtn.addEventListener('click', function() {
                if (sidebar.style.transform === 'translateX(0px)' || sidebar.style.transform === '') {
                    sidebar.style.transform = 'translateX(-100%)';
                    overlay.style.display = 'none';
                } else {
                    sidebar.style.transform = 'translateX(0)';
                    overlay.style.display = 'block';
                }
            });
            
            // 点击遮罩层隐藏侧边栏
            overlay.addEventListener('click', function() {
                sidebar.style.transform = 'translateX(-100%)';
                overlay.style.display = 'none';
            });
            
            // 窗口大小变化时检查
            function checkScreenSize() {
                const isMobile = window.innerWidth <= 768;
                
                if (isMobile) {
                    menuBtn.style.display = 'flex';
                    sidebar.style.transition = 'transform 0.3s ease';
                    sidebar.style.transform = 'translateX(-100%)';
                } else {
                    menuBtn.style.display = 'none';
                    sidebar.style.transform = 'translateX(0)';
                    overlay.style.display = 'none';
                }
            }
            
            // 初始检查
            checkScreenSize();
            
            // 监听窗口大小变化
            window.addEventListener('resize', checkScreenSize);
        }
    }
    
    // 优化表格在移动设备上的显示
    function optimizeTablesForMobile() {
        const tables = document.querySelectorAll('table');
        
        tables.forEach(table => {
            if (window.innerWidth <= 768) {
                // 创建一个新的容器，设置为overflow-x: auto
                const wrapper = document.createElement('div');
                wrapper.style.overflowX = 'auto';
                wrapper.style.marginBottom = '1rem';
                
                // 移动表格到容器中
                table.parentNode.insertBefore(wrapper, table);
                wrapper.appendChild(table);
            }
        });
    }
    
    // 添加触摸友好的按钮样式
    function enhanceTouchTargets() {
        // 增加按钮尺寸
        const buttons = document.querySelectorAll('button, .btn, .admin-btn');
        buttons.forEach(btn => {
            if (window.innerWidth <= 768) {
                const currentPadding = window.getComputedStyle(btn).padding;
                if (parseInt(currentPadding) < 10) {
                    btn.style.padding = '10px 15px';
                }
            }
        });
        
        // 增加输入框尺寸
        const inputs = document.querySelectorAll('input, select, textarea');
        inputs.forEach(input => {
            if (window.innerWidth <= 768) {
                input.style.fontSize = '16px'; // 防止iOS自动放大
            }
        });
    }
    
    // 初始化所有响应式功能
    setupMobileSidebar();
    optimizeTablesForMobile();
    enhanceTouchTargets();
    
    // 窗口大小变化时重新应用优化
    window.addEventListener('resize', function() {
        optimizeTablesForMobile();
        enhanceTouchTargets();
    });
});