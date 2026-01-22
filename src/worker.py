import jinja2
from fastapi import FastAPI, HTTPException, Depends, Request
from workers import WorkerEntrypoint
from schemas import AuthModel
import hashlib
from datetime import datetime, timedelta
import jwt
from typing import Any
from schemas import BaseResponse
import traceback

environment = jinja2.Environment()
template = environment.from_string("Hello, {{ name }}!")
ALGORITHM = "HS256"

app = FastAPI()


@app.exception_handler(Exception)
async def http_exception_handler(request: Request, exc: Exception):
    error_stack = traceback.format_exc()
    print(f"Global Exception Caught: {error_stack}")
    return BaseResponse(
        state="error",
        message=f'服务器内部错误: {str(exc)}',
        data={"detail": error_stack}
    )


@app.get("/")
async def root():
    message = "This is an example of FastAPI with Jinja2 - go to /hi/<name> to see a template rendered"
    return {"message": message}


def create_access_token(data: dict, secret: str):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret, algorithm="HS256")  # PyJWT 默认返回字符串


def verify_token(token: str, secret: str):
    try:
        # 使用从 env 传入的 secret 进行解密
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Token 无效或已过期")


def get_cloudflare_env():
    # 在本地 Swagger 环境中，这里返回 None
    # 在实际 Cloudflare 运行时，asgi-fetch 会覆盖这个值
    return None


@app.post("/register")
async def register(auth: AuthModel, env: Any = Depends(get_cloudflare_env)) -> BaseResponse:
    db = env.DB
    pwd_hash = hashlib.sha256(auth.password.encode()).hexdigest()
    try:
        await db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").bind(auth.username,
                                                                                           pwd_hash).run()
        return BaseResponse(message="注册成功")
    except:
        return BaseResponse(state='error', message="注册失败")


@app.post("/login")
async def login(auth: AuthModel, env: Any = Depends(get_cloudflare_env)) -> BaseResponse:
    db = env.DB
    # 从 Secret Store 中读取 SECRET_KEY
    # 注意：如果忘记设置，env.SECRET_KEY 会导致代码报错，这里可以做个保护
    jwt_secret = getattr(env, "SECRET_KEY", None)
    if not jwt_secret:
        return BaseResponse(state='error', message="SECRET_KEY 未设置")

    pwd_hash = hashlib.sha256(auth.password.encode()).hexdigest()

    user = await db.prepare(
        "SELECT * FROM users WHERE username = ? AND password_hash = ?"
    ).bind(auth.username, pwd_hash).first()

    if not user:
        return BaseResponse(state='error', message="用户名或密码错误")

    # 传入从 env 获取的密钥生成 Token
    token = create_access_token(data={"sub": user["username"], "id": user["id"]}, secret=jwt_secret)

    return BaseResponse(message="登录成功", data={"access_token": token, "token_type": "bearer"})


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi

        return await asgi.fetch(app, request.js_object, self.env)
