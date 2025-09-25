from app import app, db
from models import User

with app.app_context():
    # 查找admin用户
    admin_user = User.query.filter_by(username='admin').first()
    
    if admin_user:
        # 设置新的管理员密码
        new_password = 'admin123'
        admin_user.set_password(new_password)
        db.session.commit()
        print(f"成功更新管理员用户密码为: {new_password}")
    else:
        # 如果admin用户不存在，创建一个新的
        admin_user = User(username='admin', is_admin=True)
        admin_user.set_password('admin123')
        db.session.add(admin_user)
        db.session.commit()
        print("成功创建管理员用户，密码为: admin123")