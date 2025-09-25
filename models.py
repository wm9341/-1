from flask_sqlalchemy import SQLAlchemy
from passlib.hash import pbkdf2_sha256
from datetime import datetime, timedelta

# 初始化数据库
db = SQLAlchemy()

# 获取北京时间（UTC+8）
def get_beijing_time():
    return datetime.utcnow() + timedelta(hours=8)

# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=get_beijing_time)
    is_admin = db.Column(db.Boolean, default=False)  # 添加管理员字段
    is_active = db.Column(db.Boolean, default=True)  # 用户账户是否活跃
    user_id = db.Column(db.String(6), unique=True, nullable=True)  # 5-6位用户ID，用于登录
    is_owner = db.Column(db.Boolean, default=False)  # 系统主人字段
    is_co_owner = db.Column(db.Boolean, default=False)  # 系统副主字段
    
    # 设置密码，使用passlib进行加密
    def set_password(self, password):
        self.password_hash = pbkdf2_sha256.hash(password)
    
    # 验证密码
    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)
    
    # Flask-Login所需的属性和方法
    @property
    def is_authenticated(self):
        # 所有用户都被认为是已认证的
        return True
    
    @property
    def is_anonymous(self):
        # 普通用户不是匿名用户
        return False
    
    def get_id(self):
        # 返回用户的唯一标识符
        return str(self.id)

# 联飞信息模型
class FlightEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)  # 联飞活动名称
    description = db.Column(db.Text, nullable=True)  # 活动描述
    start_time = db.Column(db.DateTime, nullable=False)  # 活动开始时间
    end_time = db.Column(db.DateTime, nullable=True)  # 活动结束时间（可选）
    location = db.Column(db.String(200), nullable=True)  # 活动地点/航线
    contact_person = db.Column(db.String(100), nullable=True)  # 负责人/联系人
    max_participants = db.Column(db.Integer, default=0)  # 最大参与人数(0表示无限制)
    status = db.Column(db.String(20), default='upcoming')  # 活动状态: upcoming, ongoing, completed, canceled
    notes = db.Column(db.Text, nullable=True)  # 活动说明/公告
    created_at = db.Column(db.DateTime, default=get_beijing_time)
    participants = db.relationship('Participant', backref='flight_event', lazy=True)

# 参与者模型
class Participant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    flight_event_id = db.Column(db.Integer, db.ForeignKey('flight_event.id'), nullable=False)
    pilot_name = db.Column(db.String(80), nullable=False)  # 飞行员名字
    flight_number = db.Column(db.String(20), nullable=False)  # 航班号
    aircraft_type = db.Column(db.String(50), nullable=False)  # 机型
    qq_number = db.Column(db.String(20), nullable=False)  # QQ号码
    registered_at = db.Column(db.DateTime, default=get_beijing_time)
    
    # 添加唯一约束，确保一个用户在一个联飞活动中只能报名一次
    __table_args__ = (db.UniqueConstraint('user_id', 'flight_event_id', name='_user_flight_uc'),)

# 管制员模型
class Controller(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)  # 管制员名称
    frequency = db.Column(db.String(20), nullable=False)  # 管制频率
    control_range = db.Column(db.String(200), nullable=False)  # 管制范围
    created_at = db.Column(db.DateTime, default=get_beijing_time)
    updated_at = db.Column(db.DateTime, default=get_beijing_time, onupdate=get_beijing_time)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # 关联用户ID
    user = db.relationship('User', backref='controller', lazy=True)  # 与用户建立关系

# 操作日志模型
class OperationLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    operator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # 操作人ID
    operator = db.relationship('User', foreign_keys=[operator_id])
    action_type = db.Column(db.String(50), nullable=False)  # 操作类型: user_register, user_create, user_delete, make_admin, remove_admin
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # 目标用户ID
    target_user = db.relationship('User', foreign_keys=[target_user_id])
    details = db.Column(db.Text, nullable=True)  # 操作详情
    created_at = db.Column(db.DateTime, default=get_beijing_time)  # 操作时间