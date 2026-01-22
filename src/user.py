# -*- coding: utf-8 -*-
# @Author: sunkai
# @Time: 2026/1/22 11:28
# @File: user.py
# @Project: sk-server
# Software: PyCharm
import hashlib
from datetime import datetime, timedelta
import jwt
from typing import Any
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

ALGORITHM = "HS256"
router = APIRouter(prefix="/user")


def create_access_token(data: dict, secret: str):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(hours=24)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, secret, algorithm="HS256") # PyJWT 默认返回字符串


def verify_token(token: str, secret: str):
    try:
        # 使用从 env 传入的 secret 进行解密
        payload = jwt.decode(token, secret, algorithms=["HS256"])
        return payload
    except:
        raise HTTPException(status_code=401, detail="Token 无效或已过期")


# --- 路由 ---
class AuthModel(BaseModel):
    username: str
    password: str

def get_cloudflare_env():
    # 在本地 Swagger 环境中，这里返回 None
    # 在实际 Cloudflare 运行时，asgi-fetch 会覆盖这个值
    return None


@router.post("/register")
async def register(auth: AuthModel, env: Any = Depends(get_cloudflare_env)):
    db = env.DB
    pwd_hash = hashlib.sha256(auth.password.encode()).hexdigest()
    try:
        await db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").bind(auth.username,
                                                                                           pwd_hash).run()
        return {"message": "注册成功"}
    except:
        raise HTTPException(status_code=400, detail="用户已存在")


@router.post("/login")
async def login(auth: AuthModel, env: Any = Depends(get_cloudflare_env)):
    db = env.DB
    # 从 Secret Store 中读取 SECRET_KEY
    # 注意：如果忘记设置，env.SECRET_KEY 会导致代码报错，这里可以做个保护
    jwt_secret = getattr(env, "SECRET_KEY", None)
    if not jwt_secret:
        raise HTTPException(status_code=500, detail="服务器配置错误：缺少 SECRET_KEY")

    pwd_hash = hashlib.sha256(auth.password.encode()).hexdigest()

    user = await db.prepare(
        "SELECT * FROM users WHERE username = ? AND password_hash = ?"
    ).bind(auth.username, pwd_hash).first()

    if not user:
        raise HTTPException(status_code=401, detail="账号或密码错误")

    # 传入从 env 获取的密钥生成 Token
    token = create_access_token(data={"sub": user["username"], "id": user["id"]}, secret=jwt_secret)

    return {"access_token": token, "token_type": "bearer"}
