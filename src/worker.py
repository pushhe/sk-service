import jinja2
from fastapi import FastAPI, Request
from workers import WorkerEntrypoint
from schemas import LoginSchema
from user import router

environment = jinja2.Environment()
template = environment.from_string("Hello, {{ name }}!")

app = FastAPI()


@app.get("/")
async def root():
    message = "This is an example of FastAPI with Jinja2 - go to /hi/<name> to see a template rendered"
    return {"message": message}


@app.get("/hi/{name}")
async def say_hi(name: str):
    message = template.render(name=name)
    return {"message": message}


@app.get("/env")
async def env(req: Request):
    env = req.scope["env"]
    message = f"Here is an example of getting an environment variable: {env.MESSAGE}"
    return {"message": message}


@app.post("/login")
async def login(req: LoginSchema):
    return {"name": req.username, "password": req.password}


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi

        return await asgi.fetch(app, request.js_object, self.env)

app.include_router(router)