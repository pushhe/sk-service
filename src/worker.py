import jinja2
from fastapi import FastAPI, HTTPException, Depends, Request, status
from fastapi.responses import JSONResponse
from workers import WorkerEntrypoint
from schemas import AuthModel
import hashlib
from datetime import datetime, timedelta
import jwt
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from schemas import BaseResponse
import traceback

environment = jinja2.Environment()
template = environment.from_string("Hello, {{ name }}!")
ALGORITHM = "HS256"
security = HTTPBasic()

app = FastAPI(docs_url=None, redoc_url=None)


@app.exception_handler(Exception)
async def http_exception_handler(request: Request, exc: Exception):
    error_stack = traceback.format_exc()
    print(f"Global Exception Caught: {error_stack}")
    return JSONResponse(
        status_code=500,
        content={"state": "error", "message": str(exc), "detail": error_stack},
    )


async def authenticate_docs(credentials: HTTPBasicCredentials = Depends(security), request: Request = None):
    env = request.scope["env"]
    admin_user = env.DOC_USER
    admin_pass = env.DOC_PASS
    print(f"doc_user: {admin_user}, doc_pass: {admin_pass}")
    print(f"admin_user: {credentials.username}, admin_pass: {credentials.password}")

    if credentials.username != admin_user or credentials.password != admin_pass:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )


@app.get("/docs", include_in_schema=False)
async def overridden_swagger(username: str = Depends(authenticate_docs)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")


@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint(username: str = Depends(authenticate_docs)):
    from fastapi.openapi.utils import get_openapi
    return get_openapi(title="FastAPI", version="1.0.0", routes=app.routes)


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


@app.post("/register")
async def register(auth: AuthModel, request: Request) -> BaseResponse:
    db = request.scope.get("env").DB
    pwd_hash = hashlib.sha256(auth.password.encode()).hexdigest()
    try:
        await db.prepare("INSERT INTO users (username, password_hash) VALUES (?, ?)").bind(auth.username,
                                                                                           pwd_hash).run()
        return BaseResponse(message="注册成功")
    except:
        return BaseResponse(state='error', message="注册失败")


@app.post("/login")
async def login(auth: AuthModel, request: Request) -> BaseResponse:
    env = request.scope["env"]
    db = env.DB
    jwt_secret = await env.SECRET_KEY.get()
    if not jwt_secret:
        return BaseResponse(state='error', message="SECRET_KEY 未设置")

    pwd_hash = hashlib.sha256(auth.password.encode()).hexdigest()

    user = await db.prepare(
        "SELECT * FROM users WHERE username = ? AND password_hash = ?"
    ).bind(auth.username, pwd_hash).first()

    if not user:
        return BaseResponse(state='error', message="用户名或密码错误")

    user_data = user.to_py()
    # 传入从 env 获取的密钥生成 Token
    token = create_access_token(data={"sub": user_data["username"], "id": user_data["id"]}, secret=jwt_secret)

    return BaseResponse(message="登录成功", data={"access_token": token, "token_type": "bearer"})


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi

        return await asgi.fetch(app, request.js_object, self.env)
