# WSGI入口文件
# 用于生产环境中使用WSGI服务器（如Gunicorn）运行应用

from app import app

if __name__ == '__main__':
    app.run()