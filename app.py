from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from functools import wraps
from models import db, User, FlightEvent, Participant, Controller, OperationLog, Approval, get_beijing_time
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

# 集团管理页面装饰器（不需要登录）
def group_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 不检查用户是否登录，直接允许访问
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
        
        # 尝试导入新添加的模型类并创建测试数据
        try:
            from models import Airline, Complaint, Suggestion
            
            # 创建集团航司测试数据（如果不存在）
            if not Airline.query.first():
                airline1 = Airline(
                    name="长征航空",
                    code="LMJ",
                    description="长征航空是集团旗下的主要航空公司，提供国内和国际航线服务。"
                )
                airline2 = Airline(
                    name="蓝天航空",
                    code="LTA",
                    description="蓝天航空专注于短途航线和支线航空服务，覆盖全国主要城市。"
                )
                db.session.add_all([airline1, airline2])
                db.session.commit()
            
            # 获取管理员用户作为测试数据的提交人
            admin_user = User.query.filter_by(username='admin').first()
            if admin_user:
                # 创建投诉测试数据（如果不存在）
                if not Complaint.query.first():
                    complaint1 = Complaint(
                        user_id=admin_user.id,
                        title="航班延误问题",
                        content="最近的航班经常延误，希望能够改善航班准点率。",
                        status="processing"
                    )
                    complaint2 = Complaint(
                        user_id=admin_user.id,
                        title="服务态度问题",
                        content="部分机组人员服务态度不佳，影响飞行体验。",
                        status="pending"
                    )
                    db.session.add_all([complaint1, complaint2])
                    db.session.commit()
                
                # 创建建议与意见测试数据（如果不存在）
                if not Suggestion.query.first():
                    suggestion1 = Suggestion(
                        user_id=admin_user.id,
                        title="增加会员福利",
                        content="建议增加会员积分兑换更多福利的选项，提高会员满意度。",
                        status="implemented"
                    )
                    suggestion2 = Suggestion(
                        user_id=admin_user.id,
                        title="优化在线值机系统",
                        content="在线值机系统有时响应较慢，建议进行系统优化。",
                        status="processing"
                    )
                    db.session.add_all([suggestion1, suggestion2])
                    db.session.commit()
        except Exception as e:
            print(f"创建测试数据时出错: {str(e)}")

# 在应用启动时创建数据库表
create_tables()

# 主页路由
@app.route('/')
def index():
    # 获取所有联飞活动
    all_flights = FlightEvent.query.all()
    
    # 获取集团航司信息
    try:
        # 尝试导入新添加的模型类
        from models import Airline, Complaint, Suggestion
        # 获取所有集团航司
        all_airlines = Airline.query.all()
        # 获取最新的投诉和建议(限制显示数量)
        latest_complaints = Complaint.query.order_by(Complaint.created_at.desc()).limit(3).all()
        latest_suggestions = Suggestion.query.order_by(Suggestion.created_at.desc()).limit(3).all()
    except Exception as e:
        # 如果模型类不存在或查询出错，设置为空列表
        all_airlines = []
        latest_complaints = []
        latest_suggestions = []
    
    # 传递所有数据到模板
    return render_template('index.html', flights=all_flights, airlines=all_airlines,
                           complaints=latest_complaints, suggestions=latest_suggestions)

# 系统访问页面路由
@app.route('/system_access.html')
def system_access():
    return render_template('system_access.html')

# 生成唯一用户ID的辅助函数
def generate_random_user_id():
    import random
    import string
    
    # 生成5-6位随机数字ID
    # 随机决定是5位还是6位
    length = random.choice([5, 6])
    # 生成指定长度的随机数字字符串
    return ''.join(random.choices(string.digits, k=length))

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

# 管理员后台首页（需要登录和管理员权限）
@app.route('/admin/dashboard')
@login_required
@admin_required

def admin_dashboard():
    # 获取系统统计信息
    user_count = User.query.count()
    controller_count = Controller.query.count()
    event_count = FlightEvent.query.count()
    
    # 计算已报名活动的人数（所有活动的参与者总数）
    participant_count = Participant.query.count()
    
    # 获取最近的操作日志
    recent_logs = OperationLog.query.order_by(OperationLog.created_at.desc()).limit(10).all()
    
    return render_template('admin/dashboard.html', user_count=user_count, controller_count=controller_count, 
                           event_count=event_count, participant_count=participant_count, recent_logs=recent_logs)

# 用户管理页面
@app.route('/admin/users')
@group_admin_required
def admin_users():
    # 获取所有用户
    users = User.query.all()
    # 返回用户管理页面
    return render_template('admin/users.html', users=users)

# 操作记录页面
@app.route('/admin/operation_logs')
@group_admin_required
def admin_operation_logs():
    print("访问操作记录页面，正在加载数据...")
    # 获取所有操作记录
    logs = OperationLog.query.order_by(OperationLog.created_at.desc()).all()
    # 获取所有用户，用于显示操作人和目标用户的用户名
    users = User.query.all()
    # 将用户列表转换为字典，方便模板中查找
    user_dict = {user.id: user for user in users}
    # 返回操作记录页面
    return render_template('admin/operation_logs.html', logs=logs, users=user_dict)

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
@admin_required
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
        
        # 删除与该用户相关的所有审批记录
        Approval.query.filter_by(user_id=user_id).delete()
        
        # 如果该用户是审批人，也需要处理相关审批记录
        Approval.query.filter_by(approved_by=user_id).delete()
        
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

# 联飞活动管理页面（需要登录认证）
@app.route('/admin/flight_events')
@login_required
def admin_flight_events():
    # 获取所有联飞活动
    events = FlightEvent.query.all()
    # 返回联飞活动管理页面
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

# 编辑联飞活动
@app.route('/admin/flight_events/edit', methods=['POST'])
@admin_required
def admin_edit_flight_event():
    try:
        # 获取表单数据
        event_id = request.form.get('event_id')
        event_name = request.form.get('event_name')
        event_description = request.form.get('event_description', '')
        event_start_time_str = request.form.get('event_start_time')
        event_location = request.form.get('event_location', '')
        event_contact_person = request.form.get('event_contact_person', '')
        event_max_participants = int(request.form.get('event_max_participants', 0))
        event_status = request.form.get('event_status', 'upcoming')
        event_notes = request.form.get('event_notes', '')
        
        # 验证必填字段
        if not event_id or not event_name or not event_start_time_str:
            flash('活动ID、名称和开始时间为必填项', 'danger')
            return redirect(url_for('admin_flight_events'))
        
        # 获取要编辑的活动
        event = FlightEvent.query.get_or_404(event_id)
        
        # 转换日期时间格式
        try:
            # 处理datetime-local格式 (YYYY-MM-DDTHH:MM)
            event_start_time = datetime.strptime(event_start_time_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('日期时间格式不正确，请使用正确的格式', 'danger')
            return redirect(url_for('admin_flight_events'))
        
        # 更新活动信息
        event.name = event_name
        event.description = event_description
        event.start_time = event_start_time
        event.location = event_location
        event.contact_person = event_contact_person
        event.max_participants = event_max_participants
        event.status = event_status
        event.notes = event_notes
        
        # 提交更改到数据库
        db.session.commit()
        flash('联飞活动更新成功', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'更新联飞活动时出错: {str(e)}', 'danger')
    
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

# 管制员管理页面
@app.route('/admin/controllers')
@group_admin_required
def admin_controllers():
    # 获取所有管制员
    controllers = Controller.query.all()
    # 获取所有用户
    users = User.query.all()
    # 返回管制员管理页面
    return render_template('admin/controllers.html', controllers=controllers, users=users)

# 管理员投诉管理页面
@app.route('/admin/complaints')
@login_required
@admin_required
def admin_complaints():
    try:
        from models import Complaint
        # 获取所有投诉，按创建时间倒序排列
        complaints = Complaint.query.order_by(Complaint.created_at.desc()).all()
    except Exception as e:
        complaints = []
        flash(f'获取投诉列表时出错: {str(e)}', 'danger')
    return render_template('admin/admin_complaints.html', complaints=complaints)

# 管理员建议与意见管理页面
@app.route('/admin/suggestions')
@login_required
@admin_required
def admin_suggestions():
    try:
        from models import Suggestion
        # 获取所有建议与意见，按创建时间倒序排列
        suggestions = Suggestion.query.order_by(Suggestion.created_at.desc()).all()
    except Exception as e:
        suggestions = []
        flash(f'获取建议列表时出错: {str(e)}', 'danger')
    return render_template('admin/admin_suggestions.html', suggestions=suggestions)

# 更新建议状态
@app.route('/admin/suggestions/update_status/<int:suggestion_id>/<status>', methods=['POST'])
@login_required
@admin_required
def admin_suggestions_update_status(suggestion_id, status):
    try:
        from models import Suggestion
        # 查找建议
        suggestion = Suggestion.query.get_or_404(suggestion_id)
        
        # 更新状态
        suggestion.status = status
        db.session.commit()
        
        flash('建议状态更新成功！', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'更新建议状态失败: {str(e)}', 'danger')
    return redirect(url_for('admin_suggestions'))

# 更新投诉状态
@app.route('/admin/complaints/update_status/<int:complaint_id>/<status>', methods=['POST'])
@login_required
@admin_required
def admin_complaints_update_status(complaint_id, status):
    try:
        from models import Complaint
        # 查找投诉
        complaint = Complaint.query.get_or_404(complaint_id)
        
        # 更新状态
        complaint.status = status
        db.session.commit()
        
        flash('投诉状态更新成功！', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'更新投诉状态失败: {str(e)}', 'danger')
    return redirect(url_for('admin_complaints'))

# 集团航司管理
@app.route('/admin/airlines')
@login_required
@admin_required
def admin_airlines():
    from models import Airline
    airlines = Airline.query.order_by(Airline.created_at.desc()).all()
    return render_template('admin/admin_airlines.html', airlines=airlines)

# 添加集团航司
@app.route('/admin/airlines/add', methods=['POST'])
@login_required
@admin_required
def admin_airlines_add():
    from models import Airline
    from datetime import datetime
    
    airline_name = request.form.get('airline_name')
    airline_group_number = request.form.get('airline_group_number')
    airline_manager = request.form.get('airline_manager')
    airline_manager_qq = request.form.get('airline_manager_qq')
    
    # 验证输入
    if not airline_name:
        flash('请填写必填字段', 'error')
        return redirect(url_for('admin_airlines'))
    
    # 创建新航司
    new_airline = Airline(
        name=airline_name,
        group_number=airline_group_number,
        manager=airline_manager,
        manager_qq=airline_manager_qq,
        created_at=datetime.utcnow()
    )
    
    try:
        db.session.add(new_airline)
        db.session.commit()
        flash('集团航司添加成功', 'success')
    except Exception as e:
        db.session.rollback()
        flash('添加失败，请重试', 'error')
    
    return redirect(url_for('admin_airlines'))

# 编辑集团航司
@app.route('/admin/airlines/edit', methods=['POST'])
@login_required
@admin_required
def admin_airlines_edit():
    from models import Airline
    
    airline_id = request.form.get('airline_id')
    airline_name = request.form.get('airline_name')
    airline_group_number = request.form.get('airline_group_number')
    airline_manager = request.form.get('airline_manager')
    airline_manager_qq = request.form.get('airline_manager_qq')
    
    # 验证输入
    if not airline_id or not airline_name:
        flash('请填写必填字段', 'error')
        return redirect(url_for('admin_airlines'))
    
    # 查找航司
    airline = Airline.query.get(airline_id)
    if not airline:
        flash('航司不存在', 'error')
        return redirect(url_for('admin_airlines'))
    
    # 更新航司信息
    airline.name = airline_name
    airline.group_number = airline_group_number
    airline.manager = airline_manager
    airline.manager_qq = airline_manager_qq
    
    try:
        db.session.commit()
        flash('集团航司更新成功', 'success')
    except Exception as e:
        db.session.rollback()
        flash('更新失败，请重试', 'error')
    
    return redirect(url_for('admin_airlines'))

# 删除集团航司
@app.route('/admin/airlines/delete/<int:airline_id>', methods=['POST'])
@login_required
@admin_required
def admin_airlines_delete(airline_id):
    from models import Airline
    
    airline = Airline.query.get(airline_id)
    if not airline:
        flash('航司不存在', 'error')
        return redirect(url_for('admin_airlines'))
    
    try:
        db.session.delete(airline)
        db.session.commit()
        flash('集团航司删除成功', 'success')
    except Exception as e:
        db.session.rollback()
        flash('删除失败，请重试', 'error')
    
    return redirect(url_for('admin_airlines'))

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

# 集团航司路由
@app.route('/airlines')
def airlines():
    try:
        from models import Airline
        # 获取所有集团航司
        all_airlines = Airline.query.all()
    except Exception as e:
        all_airlines = []
        flash(f'获取航司信息时出错: {str(e)}', 'danger')
    return render_template('airlines.html', airlines=all_airlines)

# 投诉路由
@app.route('/complaints', methods=['GET', 'POST'])
def complaints():
    if request.method == 'POST':
        # 提交新投诉需要登录
        if not current_user.is_authenticated:
            flash('请先登录后再提交投诉', 'danger')
            return redirect(url_for('login'))
            
        # 提交新投诉
        title = request.form.get('title')
        content = request.form.get('content')
        complaint_type = request.form.get('complaint_type')
        
        # 初始化投诉对象信息
        target_name = None
        target_qq = None
        
        # 根据投诉类型获取目标信息
        if complaint_type == 'group_member':
            target_name = request.form.get('group_member')
            # 从选项值中提取QQ号 (格式：姓名(QQ号))
            if target_name and '(' in target_name and ')' in target_name:
                qq_start = target_name.find('(') + 1
                qq_end = target_name.find(')')
                target_qq = target_name[qq_start:qq_end] if qq_start < qq_end else None
        elif complaint_type == 'airline_chairman':
            target_name = request.form.get('airline_chairman')
            # 从选项值中提取QQ号
            if target_name and '(' in target_name and ')' in target_name:
                qq_start = target_name.find('(') + 1
                qq_end = target_name.find(')')
                target_qq = target_name[qq_start:qq_end] if qq_start < qq_end else None
        elif complaint_type == 'airline_member':
            target_name = request.form.get('airline_member_name')
            target_qq = request.form.get('airline_member_qq')
            # 航司成员需要验证姓名和QQ号
            if not target_name or not target_qq:
                flash('投诉航司成员时，姓名和QQ号为必填项', 'danger')
                return redirect(url_for('complaints'))
        
        if not title or not content or not complaint_type:
            flash('投诉标题、内容和投诉对象类型为必填项', 'danger')
            return redirect(url_for('complaints'))
        
        try:
            from models import Complaint
            new_complaint = Complaint(
                user_id=current_user.id,
                title=title,
                content=content,
                status='pending',
                complaint_type=complaint_type,
                target_name=target_name,
                target_qq=target_qq
            )
            
            db.session.add(new_complaint)
            db.session.commit()
            flash('投诉提交成功，我们会尽快处理', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'提交投诉时出错: {str(e)}', 'danger')
        
        return redirect(url_for('complaints'))
    
    return render_template('complaints.html')

# 建议与意见路由
@app.route('/suggestions', methods=['GET', 'POST'])
def suggestions():
    if request.method == 'POST':
        # 提交新建议需要登录
        if not current_user.is_authenticated:
            flash('请先登录后再提交建议与意见', 'danger')
            return redirect(url_for('login'))
            
        # 提交新建议
        title = request.form.get('title')
        content = request.form.get('content')
        
        if not title or not content:
            flash('建议标题和内容为必填项', 'danger')
            return redirect(url_for('suggestions'))
        
        try:
            from models import Suggestion
            new_suggestion = Suggestion(
                user_id=current_user.id,
                title=title,
                content=content,
                status='pending'
            )
            
            db.session.add(new_suggestion)
            db.session.commit()
            flash('建议提交成功，感谢您的反馈', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'提交建议时出错: {str(e)}', 'danger')
        
        return redirect(url_for('suggestions'))
    
    return render_template('suggestions.html')

# 审批路由 - 用户查看和提交审批
@app.route('/approvals', methods=['GET', 'POST'])
def approvals():
    if request.method == 'POST':
        # 提交新审批需要登录
        if not current_user.is_authenticated:
            flash('请先登录后再提交审批申请', 'danger')
            return redirect(url_for('login'))
            
        # 提交新审批
        title = request.form.get('title')
        content = request.form.get('content')
        approval_type = request.form.get('approval_type')
        qq_number = request.form.get('qq_number')
        
        # 由于需求变更，所有字段均为可选，不再进行必填检查
        # 创建新审批
        try:
            from models import Approval
            new_approval = Approval(
                user_id=current_user.id,
                title=title,
                content=content,
                approval_type=approval_type,
                qq_number=qq_number,
                status='pending'
            )
            
            db.session.add(new_approval)
            db.session.commit()
            flash('审批申请提交成功，等待管理员审核', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'提交审批申请时出错: {str(e)}', 'danger')
        
        return redirect(url_for('approvals'))
    
    try:
        from models import Approval
        # 获取当前用户的审批列表
        user_approvals = []
        if current_user.is_authenticated and hasattr(current_user, 'id') and current_user.id:
            user_approvals = Approval.query.filter_by(user_id=current_user.id).order_by(Approval.created_at.desc()).all()
            # 过滤掉可能的None对象
            user_approvals = [approval for approval in user_approvals if approval is not None]
    except Exception as e:
        user_approvals = []
        flash(f'获取审批列表时出错: {str(e)}', 'danger')
    
    return render_template('approvals.html', approvals=user_approvals)

# 管理员审批路由
@app.route('/admin/approvals', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_approvals():
    try:
        from models import Approval, User
        import json
        
        # 处理审批操作
        if request.method == 'POST':
            approval_id = request.form.get('approval_id')
            action = request.form.get('action')  # approve 或 reject
            
            if not approval_id or not action:
                flash('缺少必要参数', 'danger')
                return redirect(url_for('admin_approvals'))
            
            # 查找要处理的审批
            approval = Approval.query.get_or_404(approval_id)
            
            # 如果已经被拒绝，不允许再操作
            if approval.status == 'rejected':
                flash(f'审批 #{approval.id} 已经被拒绝，无法再次操作', 'danger')
                return redirect(url_for('admin_approvals'))
            
            # 当前用户信息
            current_user_id = str(current_user.id)
            is_owner = hasattr(current_user, 'is_owner') and current_user.is_owner
            is_co_owner = hasattr(current_user, 'is_co_owner') and current_user.is_co_owner
            is_admin = hasattr(current_user, 'is_admin') and current_user.is_admin
            
            # 拒绝操作可以由任何有审批权限的人执行
            if action == 'reject':
                approval.status = 'rejected'
                approval.approved_by = current_user.id
                approval.updated_at = get_beijing_time()
                db.session.commit()
                flash(f'审批 #{approval.id} 已成功拒绝', 'success')
                return redirect(url_for('admin_approvals'))
            
            # 处理同意操作
            if action == 'approve':
                # 解析现有的审批状态
                admin_approvals = json.loads(approval.admin_approvals or '{}')
                co_owner_approvals = json.loads(approval.co_owner_approvals or '{}')
                
                # 获取所有管理员和副主
                all_admins = User.query.filter_by(is_admin=True).all()
                all_co_owners = User.query.filter_by(is_co_owner=True).all()
                admin_count = len(all_admins)
                co_owner_count = len(all_co_owners)
                
                # 根据用户角色处理审批
                if is_owner:
                    # 主人只能在所有管理员和副主都同意后才能批准
                    if approval.admin_approved_count == admin_count and approval.co_owner_approved_count == co_owner_count:
                        approval.status = 'approved'
                        approval.approved_by = current_user.id
                        approval.updated_at = get_beijing_time()
                        db.session.commit()
                        flash(f'审批 #{approval.id} 已成功批准', 'success')
                    else:
                        flash(f'审批 #{approval.id} 尚未获得所有管理员和副主的同意，主人无法进行最终批准', 'danger')
                elif is_co_owner:
                    # 副主的审批 - 只有在所有管理员都同意后才能进行
                    if approval.admin_approved_count < admin_count:
                        flash(f'审批 #{approval.id} 尚未获得所有管理员的同意，副主无法进行审批', 'danger')
                    elif current_user_id not in co_owner_approvals:
                        co_owner_approvals[current_user_id] = 'approved'
                        approval.co_owner_approvals = json.dumps(co_owner_approvals)
                        approval.co_owner_approved_count += 1
                        approval.updated_at = get_beijing_time()
                        
                        # 检查是否所有管理员和副主都已同意
                        if approval.admin_approved_count == admin_count and approval.co_owner_approved_count == co_owner_count:
                            approval.status = 'owner_pending'  # 等待主人最终批准
                        else:
                            approval.status = 'co_owner_pending'  # 部分副主已批准
                        
                        db.session.commit()
                        flash(f'您已成功同意审批 #{approval.id}', 'success')
                    else:
                        flash(f'您已经对审批 #{approval.id} 进行过操作', 'info')
                elif is_admin:
                    # 管理员的审批
                    if current_user_id not in admin_approvals:
                        admin_approvals[current_user_id] = 'approved'
                        approval.admin_approvals = json.dumps(admin_approvals)
                        approval.admin_approved_count += 1
                        approval.updated_at = get_beijing_time()
                        
                        # 检查是否所有管理员都已同意
                        if approval.admin_approved_count == admin_count:
                            approval.status = 'co_owner_pending'  # 等待副主审批
                        else:
                            approval.status = 'admin_pending'  # 部分管理员已批准
                        
                        db.session.commit()
                        flash(f'您已成功同意审批 #{approval.id}', 'success')
                    else:
                        flash(f'您已经对审批 #{approval.id} 进行过操作', 'info')
                else:
                    flash('您没有审批权限', 'danger')
            
            return redirect(url_for('admin_approvals'))
        
        # 获取所有审批列表
        all_approvals = Approval.query.order_by(Approval.created_at.desc()).all()
        
        # 获取用户信息用于显示
        users = {user.id: user for user in User.query.all()}
    except Exception as e:
        all_approvals = []
        users = {}
        flash(f'获取审批列表时出错: {str(e)}', 'danger')
    
    return render_template('admin/admin_approvals.html', approvals=all_approvals, users=users)

# 审批详情路由
@app.route('/approvals/<int:approval_id>')
def approval_details(approval_id):
    try:
        from models import Approval, User
        approval = Approval.query.get_or_404(approval_id)
        
        # 确保用户只能查看自己的审批或管理员可以查看所有审批
        if approval.user_id != current_user.id and not (current_user.is_authenticated and current_user.is_admin):
            flash('您无权查看此审批', 'danger')
            return redirect(url_for('approvals'))
        
        # 获取相关用户信息
        user = User.query.get(approval.user_id)
        approved_user = User.query.get(approval.approved_by) if approval.approved_by else None
        
        # 获取所有管理员和副主的总数，用于显示审批进度
        all_admins = User.query.filter_by(is_admin=True).all()
        all_co_owners = User.query.filter_by(is_co_owner=True).all()
        all_admins_count = len(all_admins)
        all_co_owners_count = len(all_co_owners)
    except Exception as e:
        flash(f'获取审批详情时出错: {str(e)}', 'danger')
        return redirect(url_for('approvals'))
    
    # 获取所有用户数据，用于在流程图中显示审批人信息
    all_users = User.query.all()
    users_dict = {str(user.id): {'username': user.username} for user in all_users}
    
    # 确保审批数据是可JSON序列化的
    import json
    
    # 创建一个新的字典来存储可序列化的数据，并确保包含所有模板需要的字段
    approval_data = {
        'id': approval.id,
        'approval_type': approval.approval_type,
        'status': approval.status,
        'title': approval.title,
        'content': approval.content,
        'qq_number': getattr(approval, 'qq_number', None),
        'created_at': approval.created_at,
        'updated_at': getattr(approval, 'updated_at', None),
        'user_id': approval.user_id,
        'approved_by': getattr(approval, 'approved_by', None),
        'admin_approved_count': getattr(approval, 'admin_approved_count', 0),
        'co_owner_approved_count': getattr(approval, 'co_owner_approved_count', 0),
        'admin_approvals': {},
        'co_owner_approvals': {}
    }
    
    # 处理admin_approvals字段
    if hasattr(approval, 'admin_approvals') and approval.admin_approvals:
        try:
            if isinstance(approval.admin_approvals, str):
                approval_data['admin_approvals'] = json.loads(approval.admin_approvals)
            else:
                approval_data['admin_approvals'] = approval.admin_approvals
        except:
            approval_data['admin_approvals'] = {}
    
    # 处理co_owner_approvals字段
    if hasattr(approval, 'co_owner_approvals') and approval.co_owner_approvals:
        try:
            if isinstance(approval.co_owner_approvals, str):
                approval_data['co_owner_approvals'] = json.loads(approval.co_owner_approvals)
            else:
                approval_data['co_owner_approvals'] = approval.co_owner_approvals
        except:
            approval_data['co_owner_approvals'] = {}
    
    # 准备渲染模板所需的数据
    template_data = {
        'approval': approval_data,
        'user': user,
        'approved_user': approved_user,
        'all_admins_count': all_admins_count,
        'all_co_owners_count': all_co_owners_count,
        'users': users_dict
    }
    
    return render_template('approval_details.html', **template_data)

if __name__ == '__main__':
    # 创建数据库表和初始数据
    create_tables()
    # 强制启用debug模式
    debug_mode = True
    app.run(debug=debug_mode, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))