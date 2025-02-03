
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from datetime import datetime, timedelta
from pydantic import BaseModel
import re
import hashlib


import mysql.connector

try:
    Connection = mysql.connector.connect(
        host="localhost",
        user="root",
        password="123456",
        database="test"
    )
    if Connection.is_connected():
        print("成功连接到MYSQL 数据库")
        cursor = Connection.cursor()
        # cursor.execute("SELECT * FROM users")
        # results = cursor.fetchall()

except mysql.connector.Error as error:
    print(f"连接数据库时出现错误: {error}")










# 创建 FastAPI 应用实例
app = FastAPI()

# 配置允许所有跨域请求
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 允许所有源
    allow_credentials=True,
    allow_methods=["*"],  # 允许所有 HTTP 方法
    allow_headers=["*"],  # 允许所有 HTTP 头
)



# 定义注册请求模型
class RegisterRequest(BaseModel):
    username: str
    password: str

# 定义登录请求模型
class LoginRequest(BaseModel):
    username: str
    password: str

# 定义通用响应模型
class Response(BaseModel):
    code: int
    message: str
    token: str = None


import jwt
from datetime import datetime, timedelta, timezone
import pytz

# 密钥，用于签名和验证 JWT
SECRET_KEY = "your_secret_key"
# 算法，这里使用 HS256
ALGORITHM = "HS256"
# 有效期设置为 1 小时
EXPIRATION_TIME = timedelta(hours=1)
# 定义东八区时区
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')


def generate_token(user_id):
    """
    生成 JWT Token，包含用户 ID 和有效期
    :param user_id: 用户 ID
    :return: 生成的 JWT Token
    """
    # 获取当前时间并转换为东八区时间
    now = datetime.now(SHANGHAI_TZ)
    # 计算过期时间
    expiration = now + EXPIRATION_TIME
    # 将 datetime 对象转换为 Unix 时间戳
    exp_timestamp = int(expiration.timestamp())
    # 构建 JWT 的负载（payload）
    payload = {
        "user_id": user_id,
        "exp": exp_timestamp
    }
    # 生成 JWT Token
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    # 打印有效期信息
    print(f"Token 生成时的有效期至: {expiration.strftime('%Y-%m-%d %H:%M:%S')}")
    return token


def verify_token(token):
    """
    验证 JWT Token 的有效性
    :param token: 待验证的 JWT Token
    :return: 如果验证成功，返回负载信息；否则返回 None
    """
    try:
        # 验证并解码 JWT Token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # 获取过期时间
        exp_timestamp = payload.get('exp')
        if exp_timestamp:
            # 将 Unix 时间戳转换为东八区的 datetime 对象
            exp_datetime = datetime.fromtimestamp(exp_timestamp, SHANGHAI_TZ)
            print(f"Token 验证时的有效期至: {exp_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
        return payload
    except jwt.ExpiredSignatureError:
        print("Token 已过期")
    except jwt.InvalidTokenError:
        print("无效的 Token")
    return None





# 注册接口
@app.post("/reg", response_model=Response)
def register(request: RegisterRequest):
    

    if not is_valid_username(request.username):
        return {"code": 400, "message": "用户名不能为中文，并且大于6小于32字符", "token": ""}
    
    # if not is_strong_password(request.password):
    #     return {"code": 400, "message": "密码必须大小写和特殊符号和数字", "token": ""}

    request.password = md5_encrypt(request.password)
    username = request.username
    password = request.password

    #查询语句
    select_query = "SELECT * FROM users WHERE username = %s"
    #填充占位符
    cursor.execute(select_query, (request.username,))
    #执行mysql
    existing_user = cursor.fetchone()
    
    if existing_user:
        print(f"{request.username}用户名已经注册，请重新输入")
        return {"code": 400, "message": "用户名已存在，请重新输入", "token": ""}


    insert_query = """
        INSERT INTO users (username, pass)
        VALUES (%s, %s)
    """
    data = (username, password)
    cursor.execute(insert_query, data)
    Connection.commit()
    print(f"成功插入 {cursor.rowcount} 条记录,插入的ID为:{cursor.lastrowid}")

    return {"code": 200, "message": "注册成功", "token": ""}

# 登录接口
@app.post("/login", response_model=Response)
def login(request: LoginRequest):
    print(request)
    # username = request.username
    # password = request.password

    request.password = md5_encrypt(request.password)


    select_query="SELECT * FROM users WHERE username=%s AND pass=%s"
    cursor.execute(select_query, (request.username,request.password,))
    #执行mysql
    existing_user = cursor.fetchone()
    print(f"查询到的用户：{existing_user}")
    if existing_user:
        # 生成一个简单的 token
        token = generate_token(request.username)
        print(f"生成的 Token: {token}")
        payload = verify_token(token)
        if payload:
            print(f"验证成功，用户 ID: {payload['user_id']}")
        return {"code": 200, "message": "登录成功", "token": token}
    else:
       return {"code": 400, "message": "登陆失败，账号或密码错误", "token": ""} 

# islogin 接口
security = HTTPBearer()

@app.get("/islogin")
def islogin(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        # 去除 "Bearer " 前缀
        if token.startswith("Bearer "):
            token = token[7:]
        payload = verify_token(token)
        return {"code": 200, "message": f"用户已登录{payload["user_id"]}"}
    except HTTPException as e:
        return {"code": 400, "message": e.detail}



def is_strong_password(password):
    """
    检查密码是否为强密码，即包含大小写字母、数字和特殊符号
    :param password: 待检查的密码
    :return: 如果是强密码返回 True，否则返回 False
    """
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$'
    return bool(re.match(pattern, password))


def is_valid_username(username):
    """
    检查用户名是否有效，要求不能包含中文，且长度大于 6 小于 32 字符
    :param username: 待检查的用户名
    :return: 如果用户名有效返回 True，否则返回 False
    """
    # 正则表达式用于匹配不包含中文的字符串
    pattern = r'^[^\u4e00-\u9fa5]{6,31}$'
    return bool(re.match(pattern, username))



def md5_encrypt(password):
    """
    对输入的密码进行 MD5 加密
    :param password: 待加密的密码
    :return: 加密后的十六进制字符串
    """
    # 创建 MD5 对象
    md5 = hashlib.md5()
    # 将密码编码为字节类型
    password_bytes = password.encode('utf-8')
    # 更新 MD5 对象的内容
    md5.update(password_bytes)
    # 获取加密后的十六进制字符串
    encrypted_password = md5.hexdigest()
    return encrypted_password

##  uvicorn main:app --host 0.0.0.0 --port 8000