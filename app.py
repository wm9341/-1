from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
from models import db, User, FlightEvent, Participant, Controller, OperationLog, get_beijing_time
from datetime import datetime
import os
import re
from permissions import co_owner_required, is_target_owner

app = Flask(__name__)
# 配置数据库
# 从环境变量获取密钥，如果没有则使用默认值（仅开发环境使用）
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key')
# 配置数据库路径，如果环境变量中设置了则使用环境变量中的值
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///flight_manager.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化数据库
with app.app_context():
    db.init_app(app)

# 配置登录管理器
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# 管理员权限装饰器
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('您需要管理员权限才能访问此页面')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# 创建数据库表和初始数据
def create_tables():
    with app.app_context():
        db.create_all()
        # 创建初始联飞活动（如果不存在）
        if not FlightEvent.query.first():
            current_time = datetime.now()
            from datetime import timedelta
            initial_event = FlightEvent(
                name="冬季联合飞行活动",
                description="这是一个示例联飞活动，欢迎所有飞行员参加！",
                start_time=current_time,
                end_time=current_time + timedelta(hours=3),
                location="北京-上海航线",
                contact_person="管理员",
                max_participants=50,
                status="upcoming",
                notes="请提前准备好飞行计划和相关文件"
            )
            db.session.add(initial_event)
            db.session.commit()
        
        # 创建管理员用户（如果不存在）
        if not User.query.filter_by(username='admin').first():
            admin_user = User(username='admin', is_admin=True)
            admin_user.set_password('admin123')
            db.session.add(admin_user)
            db.session.commit()

# 在应用启动时创建数据库表
create_tables()

# 主页路由
@app.route('/')
def index():
    # 获取所有联飞活动
    all_flights = FlightEvent.query.all()
    return render_template('index.html', flights=all_flights)

# 生成唯一用户ID的辅助函数
def generate_random_user_id():
    import random
    import string
    import time
    
    # 使用时间戳+随机字符串的组合，确保唯一性
    timestamp = str(int(time.time() * 1000))[-5:]
    random_str = ''.join(random.choices(string.ascii_uppercase + string.digits, k=3))
    
    # 生成格式为：字母数字混合的8位ID
    user_id = f"{timestamp}{random_str}"
    
    return user_id

# 登录路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_identifier = request.form['login_identifier']  # 用户名或ID
        password = request.form['password']
        
        # 尝试通过用户名查找
        user = User.query.filter_by(username=login_identifier).first()
        
        # 如果没找到，尝试通过用户ID查找
        if not user:
            user = User.query.filter_by(user_id=login_identifier).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('用户名/ID或密码错误')
    return render_template('login.html')

# 注册路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # 检查用户名长度
        if len(username) < 3:
            flash('用户名必须至少包含3个字符')
            return redirect(url_for('register'))
            
        # 检查用户名格式（只能包含英文和数字）
        if not re.match(r'^[a-zA-Z0-9]+$', username):
            flash('用户名只能包含英文和数字')
            return redirect(url_for('register'))
            
        # 检查密码是否一致
        if password != confirm_password:
            flash('两次输入的密码不一致，请重新输入')
            return redirect(url_for('register'))
        
        # 检查密码长度
        if len(password) < 6:
            flash('密码必须至少包含6个字符')
            return redirect(url_for('register'))
            
        # 检查密码是否包含数字和字母
        if not (re.search(r'[a-zA-Z]', password) and re.search(r'\d', password)):
            flash('密码必须包含至少一个字母和一个数字')
            return redirect(url_for('register'))
        
        # 检查用户名是否已存在
        if User.query.filter_by(username=username).first():
            flash('用户名已存在')
            return redirect(url_for('register'))
        
        # 创建新用户
        new_user = User(username=username)
        new_user.set_password(password)
        
        # 生成唯一的5-6位用户ID
        while True:
            user_id = generate_random_user_id()
            if not User.query.filter_by(user_id=user_id).first():
                break
        new_user.user_id = user_id
        
        db.session.add(new_user)
        db.session.commit()
        
        # 记录用户注册日志
        register_log = OperationLog(
            operator_id=new_user.id,
            action_type='user_register',
            target_user_id=new_user.id,
            details=f'用户注册成功，用户名: {username}，用户ID: {user_id}'
        )
        db.session.add(register_log)
        db.session.commit()
        
        flash(f'注册成功，您的用户ID是：{user_id}，请妥善保管并使用它或用户名登录')
        return redirect(url_for('login'))
    return render_template('register.html')

# 仪表盘路由（登录后访问）
@app.route('/dashboard')
@login_required
def dashboard():
    # 获取当前活跃的联飞活动
    active_events = FlightEvent.query.all()
    # 获取当前用户已参加的联飞活动
    user_participations = Participant.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', events=active_events, participations=user_participations)

# 报名参加联飞活动路由
@app.route('/join_flight/<int:event_id>', methods=['GET', 'POST'])
@login_required
def join_flight(event_id):
    event = FlightEvent.query.get_or_404(event_id)
    
    # 检查用户是否已报名此活动
    existing_participation = Participant.query.filter_by(
        user_id=current_user.id,
        flight_event_id=event_id
    ).first()
    
    if existing_participation:
        flash('您已经报名参加了此联飞活动')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        pilot_name = request.form['pilot_name']
        flight_number = request.form['flight_number']
        qq_number = request.form['qq_number']
        aircraft_type = request.form['aircraft_type']
        
        # 创建新的参与者记录
        new_participation = Participant(
            user_id=current_user.id,
            flight_event_id=event_id,
            pilot_name=pilot_name,
            flight_number=flight_number,
            qq_number=qq_number,
            aircraft_type=aircraft_type
        )
        
        db.session.add(new_participation)
        db.session.commit()
        
        flash(f'成功报名参加{event.name}！')
        return redirect(url_for('dashboard'))
    
    return render_template('join_flight.html', event=event)

# 查看联飞活动详情路由
@app.route('/flight_details/<int:event_id>')
@login_required
def flight_details(event_id):
    event = FlightEvent.query.get_or_404(event_id)
    participants = Participant.query.filter_by(flight_event_id=event_id).all()
    return render_template('flight_details.html', event=event, participants=participants)

# 登出路由
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# 管理员后台首页
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # 获取统计信息
    total_users = User.query.count()
    total_events = FlightEvent.query.count()
    total_participants = Participant.query.count()
    
    return render_template('admin/dashboard.html', 
                          total_users=total_users, 
                          total_events=total_events, 
                          total_participants=total_participants)

# 管理员用户管理页面
@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)

# 主人账号操作记录页面
@app.route('/admin/operation_logs')
@login_required
def admin_operation_logs():
    # 只允许系统主人查看操作记录
    if not hasattr(current_user, 'is_owner') or not current_user.is_owner:
        flash('只有系统主人才可以查看操作记录', 'danger')
        return redirect(url_for('dashboard'))
    
    # 获取所有操作记录，并按时间倒序排列
    logs = OperationLog.query.order_by(OperationLog.created_at.desc()).all()
    
    # 获取相关用户的信息，用于在模板中显示用户名
    user_ids = set()
    for log in logs:
        user_ids.add(log.operator_id)
        user_ids.add(log.target_user_id)
    
    users = {user.id: user for user in User.query.filter(User.id.in_(user_ids)).all()}
    
    return render_template('admin/operation_logs.html', logs=logs, users=users)

# 添加管理员权限
@app.route('/admin/users/make_admin/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_make_admin(user_id):
    try:
        # 检查是否为系统主人
        if not hasattr(current_user, 'is_owner') or not current_user.is_owner:
            flash('只有系统主人才可以添加管理员权限', 'danger')
            return redirect(url_for('admin_users'))
        
        # 不能操作当前登录用户自己
        if user_id == current_user.id:
            flash('不能操作当前登录用户的权限', 'danger')
            return redirect(url_for('admin_users'))
            
        user = User.query.get_or_404(user_id)
        user.is_admin = True
        db.session.commit()
        
        # 记录添加管理员日志
        admin_log = OperationLog(
            operator_id=current_user.id,
            action_type='make_admin',
            target_user_id=user_id,
            details=f'系统主人 {current_user.username} 将用户 {user.username} 提升为管理员'
        )
        db.session.add(admin_log)
        db.session.commit()
        
        flash(f'用户 {user.username} 已成功提升为管理员', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'操作失败: {str(e)}', 'danger')
    return redirect(url_for('admin_users'))

# 移除管理员权限
@app.route('/admin/users/remove_admin/<int:user_id>', methods=['POST'])
@login_required
@co_owner_required
def admin_remove_admin(user_id):
    try:
        # 检查目标用户是否是主人
        if is_target_owner(user_id):
            flash('系统主人账号的管理员权限不可移除', 'danger')
            return redirect(url_for('admin_users'))
        
        # 不能操作当前登录用户自己
        if user_id == current_user.id:
            flash('不能操作当前登录用户的权限', 'danger')
            return redirect(url_for('admin_users'))
            
        user = User.query.get_or_404(user_id)
        
        # 确保至少有一个管理员存在
        admin_count = User.query.filter_by(is_admin=True).count()
        if admin_count <= 1 and user.is_admin:
            flash('系统至少需要保留一个管理员用户', 'danger')
            return redirect(url_for('admin_users'))
            
        user.is_admin = False
        db.session.commit()
        
        # 记录移除管理员日志
        remove_admin_log = OperationLog(
            operator_id=current_user.id,
            action_type='remove_admin',
            target_user_id=user_id,
            details=f'用户 {current_user.username} 移除了用户 {user.username} 的管理员权限'
        )
        db.session.add(remove_admin_log)
        db.session.commit()
        
        flash(f'用户 {user.username} 的管理员权限已成功移除', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'操作失败: {str(e)}', 'danger')
    return redirect(url_for('admin_users'))

# 删除用户
@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@co_owner_required
def admin_delete_user(user_id):
    try:
        # 不能删除当前登录用户自己
        if user_id == current_user.id:
            flash('不能删除当前登录用户', 'danger')
            return redirect(url_for('admin_users'))
            
        user = User.query.get_or_404(user_id)
        
        # 检查目标用户是否是主人
        if is_target_owner(user_id):
            flash('系统主人账号不可删除', 'danger')
            return redirect(url_for('admin_users'))
        
        # 检查目标用户是否是副主
        # 只有系统主人才可以删除副主
        if hasattr(user, 'is_co_owner') and user.is_co_owner:
            if not hasattr(current_user, 'is_owner') or not current_user.is_owner:
                flash('只有系统主人才可以删除副主账号', 'danger')
                return redirect(url_for('admin_users'))
        
        # 普通管理员不能删除其他管理员账号
        if user.is_admin and not (hasattr(current_user, 'is_owner') or hasattr(current_user, 'is_co_owner')):
            flash('管理员不可删除其他管理员账号', 'danger')
            return redirect(url_for('admin_users'))
        
        # 确保系统至少保留一个管理员（系统主人或副主执行操作时检查）
        if user.is_admin and (hasattr(current_user, 'is_owner') and current_user.is_owner):
            admin_count = User.query.filter_by(is_admin=True).count()
            if admin_count <= 1:
                flash('系统至少需要保留一个管理员用户', 'danger')
                return redirect(url_for('admin_users'))
        
        # 删除与该用户相关的所有参与者记录
        Participant.query.filter_by(user_id=user_id).delete()
        
        # 记录删除用户日志
        delete_log = OperationLog(
            operator_id=current_user.id,
            action_type='delete_user',
            target_user_id=user_id,
            details=f'用户 {current_user.username} 删除了用户 {user.username}（用户ID: {user.user_id}）'
        )
        db.session.add(delete_log)
        
        # 删除用户
        db.session.delete(user)
        db.session.commit()
        flash(f'用户 {user.username} 已成功删除', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'操作失败: {str(e)}', 'danger')
    return redirect(url_for('admin_users'))

# 管理员联飞活动管理页面
@app.route('/admin/flight_events')
@admin_required
def admin_flight_events():
    events = FlightEvent.query.all()
    return render_template('admin/flight_events.html', events=events)

# 添加联飞活动
@app.route('/admin/flight_events/add', methods=['POST'])
@admin_required
def admin_add_flight_event():
    try:
        # 获取表单数据
        event_name = request.form.get('event_name')
        event_description = request.form.get('event_description', '')
        event_start_time_str = request.form.get('event_start_time')
        event_location = request.form.get('event_location', '')
        event_contact_person = request.form.get('event_contact_person', '')
        event_max_participants = int(request.form.get('event_max_participants', 0))
        event_status = request.form.get('event_status', 'upcoming')
        event_notes = request.form.get('event_notes', '')
        
        # 验证必填字段
        if not event_name or not event_start_time_str:
            flash('活动名称和开始时间为必填项', 'danger')
            return redirect(url_for('admin_flight_events'))
        
        # 转换日期时间格式
        try:
            # 处理datetime-local格式 (YYYY-MM-DDTHH:MM)
            event_start_time = datetime.strptime(event_start_time_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('日期时间格式不正确，请使用正确的格式', 'danger')
            return redirect(url_for('admin_flight_events'))
        
        # 创建新的联飞活动
        new_event = FlightEvent(
            name=event_name,
            description=event_description,
            start_time=event_start_time,
            end_time=None,
            location=event_location,
            contact_person=event_contact_person,
            max_participants=event_max_participants,
            status=event_status,
            notes=event_notes,
            created_at=datetime.now()
        )
        
        # 添加到数据库并提交
        db.session.add(new_event)
        db.session.commit()
        flash('联飞活动添加成功', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'添加联飞活动时出错: {str(e)}', 'danger')
    
    return redirect(url_for('admin_flight_events'))

# 删除联飞活动
@app.route('/admin/flight_events/delete/<int:event_id>', methods=['POST'])
@admin_required
def admin_delete_flight_event(event_id):
    event = FlightEvent.query.get_or_404(event_id)
    
    # 删除所有相关的参与者记录
    Participant.query.filter_by(flight_event_id=event_id).delete()
    
    # 删除联飞活动
    db.session.delete(event)
    db.session.commit()
    flash('联飞活动已成功删除', 'success')
    return redirect(url_for('admin_flight_events'))

# 修改用户名（系统主人专用）
@app.route('/admin/users/update_username/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_update_username(user_id):
    # 检查是否为系统主人
    if not hasattr(current_user, 'is_owner') or not current_user.is_owner:
        flash('只有系统主人才可以修改用户名', 'danger')
        return redirect(url_for('admin_users'))
        
    user = User.query.get_or_404(user_id)
    new_username = request.form.get('new_username')
    
    # 验证新用户名
    if not new_username:
        flash('用户名不能为空', 'danger')
        return redirect(url_for('admin_users'))
        
    # 检查用户名格式（只能包含中文、英文和数字）
    if not re.match(r'^[a-zA-Z0-9\u4e00-\u9fa5]+$', new_username):
        flash('用户名只能包含中文、英文和数字', 'danger')
        return redirect(url_for('admin_users'))
        
    # 检查新用户名是否已存在
    existing_user = User.query.filter_by(username=new_username).first()
    if existing_user and existing_user.id != user.id:
        flash('用户名已存在', 'danger')
        return redirect(url_for('admin_users'))
        
    # 保存旧用户名用于日志
    old_username = user.username
    
    try:
        # 更新用户名
        user.username = new_username
        db.session.commit()
        
        flash(f'用户 {old_username} 的用户名已成功修改为 {new_username}', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'操作失败: {str(e)}', 'danger')
    return redirect(url_for('admin_users'))

# 移除副主权限
@app.route('/admin/users/remove_co_owner/<int:user_id>', methods=['POST'])
@login_required
def admin_remove_co_owner(user_id):
    try:
        # 只有系统主人才可以移除副主权限
        if not hasattr(current_user, 'is_owner') or not current_user.is_owner:
            flash('只有系统主人才可以移除副主权限', 'danger')
            return redirect(url_for('admin_users'))
        
        # 不能操作当前登录用户自己
        if user_id == current_user.id:
            flash('不能操作当前登录用户的权限', 'danger')
            return redirect(url_for('admin_users'))
            
        user = User.query.get_or_404(user_id)
        
        # 检查目标用户是否是副主
        if not hasattr(user, 'is_co_owner') or not user.is_co_owner:
            flash('该用户不是副主', 'danger')
            return redirect(url_for('admin_users'))
            
        user.is_co_owner = False
        # 如果需要，同时取消其管理员权限
        user.is_admin = False
        db.session.commit()
        
        # 记录移除副主日志
        remove_co_owner_log = OperationLog(
            operator_id=current_user.id,
            action_type='remove_co_owner',
            target_user_id=user_id,
            details=f'系统主人 {current_user.username} 移除了用户 {user.username} 的副主权限'
        )
        db.session.add(remove_co_owner_log)
        db.session.commit()
        
        flash(f'用户 {user.username} 的副主权限已成功移除', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'操作失败: {str(e)}', 'danger')
    return redirect(url_for('admin_users'))

# 管制员列表路由
@app.route('/controllers')
@login_required
def controllers_list():
    # 从数据库获取管制员数据
    controllers = Controller.query.order_by(Controller.created_at.desc()).all()
    return render_template('controllers_list.html', controllers=controllers)

# 火大系统路由 - 仅管理员可访问
@app.route('/huoda')
@login_required
@admin_required
def huoda():
    # 这里可以添加火大系统的相关逻辑
    return render_template('huoda.html')

# 管制员管理路由
@app.route('/admin/controllers')
@login_required
@admin_required
def admin_controllers():
    controllers = Controller.query.order_by(Controller.created_at.desc()).all()
    # 获取所有用户列表，用于下拉选择
    users = User.query.order_by(User.username).all()
    return render_template('admin/controllers.html', controllers=controllers, users=users)

@app.route('/admin/controllers/add', methods=['POST'])
@login_required
@admin_required
def admin_controllers_add():
    try:
        # 获取表单数据
        controller_user_id = request.form.get('controller_user_id')
        controller_name = request.form.get('controller_name')
        controller_frequency = request.form.get('controller_frequency')
        controller_range = request.form.get('controller_range')
        
        # 验证必填字段
        if not controller_user_id or not controller_name or not controller_frequency or not controller_range:
            flash('关联用户、管制员名称、频率和范围为必填项', 'danger')
            return redirect(url_for('admin_controllers'))
            
        # 验证工号长度（5-6个字符）
        if len(controller_frequency) < 5 or len(controller_frequency) > 6:
            flash('工号必须为5-6个字符', 'danger')
            return redirect(url_for('admin_controllers'))
        
        # 检查用户是否存在
        user = User.query.get(controller_user_id)
        if not user:
            flash('选择的用户不存在', 'danger')
            return redirect(url_for('admin_controllers'))
            
        # 检查用户是否已经关联了管制员
        existing_controller = Controller.query.filter_by(user_id=controller_user_id).first()
        if existing_controller:
            flash(f'用户 "{user.username}" 已经是管制员了', 'danger')
            return redirect(url_for('admin_controllers'))
        
        # 创建新的管制员
        new_controller = Controller(
            name=controller_name,
            frequency=controller_frequency,
            control_range=controller_range,
            created_at=get_beijing_time(),
            updated_at=get_beijing_time(),
            user_id=controller_user_id
        )
        
        # 添加到数据库并提交
        db.session.add(new_controller)
        db.session.commit()
        flash('管制员添加成功', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'添加管制员时出错: {str(e)}', 'danger')
    
    return redirect(url_for('admin_controllers'))

@app.route('/admin/controllers/edit', methods=['POST'])
@login_required
@admin_required
def admin_controllers_edit():
    try:
        # 获取表单数据
        controller_id = request.form.get('controller_id')
        controller_user_id = request.form.get('controller_user_id')
        controller_name = request.form.get('controller_name')
        controller_frequency = request.form.get('controller_frequency')
        controller_range = request.form.get('controller_range')
        controller_online = request.form.get('controller_online') == 'on'
        
        # 验证必填字段
        if not controller_id or not controller_user_id or not controller_name or not controller_frequency or not controller_range:
            flash('所有字段为必填项', 'danger')
            return redirect(url_for('admin_controllers'))
            
        # 验证工号长度（5-6个字符）
        if len(controller_frequency) < 5 or len(controller_frequency) > 6:
            flash('工号必须为5-6个字符', 'danger')
            return redirect(url_for('admin_controllers'))
        
        # 检查用户是否存在
        user = User.query.get(controller_user_id)
        if not user:
            flash('选择的用户不存在', 'danger')
            return redirect(url_for('admin_controllers'))
            
        # 查找要编辑的管制员
        controller = Controller.query.get_or_404(controller_id)
        
        # 检查是否有其他管制员已经关联了该用户
        if controller_user_id != str(controller.user_id if controller.user_id else ''):
            existing_controller = Controller.query.filter_by(user_id=controller_user_id).first()
            if existing_controller:
                flash(f'用户 "{user.username}" 已经是其他管制员了', 'danger')
                return redirect(url_for('admin_controllers'))
        
        # 更新管制员信息
        controller.name = controller_name
        controller.frequency = controller_frequency
        controller.control_range = controller_range
        controller.user_id = controller_user_id
        controller.updated_at = get_beijing_time()
        
        # 保存更改
        db.session.commit()
        flash('管制员信息更新成功', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'更新管制员信息时出错: {str(e)}', 'danger')
    
    return redirect(url_for('admin_controllers'))

# 获取管制员关联的用户ID路由（用于前端AJAX请求）
@app.route('/admin/controllers/get_user_id/<int:controller_id>')
@login_required
@admin_required
def admin_get_controller_user_id(controller_id):
    controller = Controller.query.get_or_404(controller_id)
    # 返回JSON格式的用户ID
    return jsonify({
        'user_id': controller.user_id
    })

@app.route('/admin/controllers/delete/<int:controller_id>', methods=['POST'])
@login_required
@admin_required
def admin_controllers_delete(controller_id):
    try:
        # 查找要删除的管制员
        controller = Controller.query.get_or_404(controller_id)
        
        # 删除管制员
        db.session.delete(controller)
        db.session.commit()
        flash('管制员已成功删除', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'删除管制员时出错: {str(e)}', 'danger')
    
    return redirect(url_for('admin_controllers'))

if __name__ == '__main__':
    # 创建数据库表和初始数据
    create_tables()
    # 从环境变量获取DEBUG模式设置，默认为False
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))