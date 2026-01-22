# -*- coding: utf-8 -*-
# @Author: sunkai
# @Time: 2026/1/20 17:36
# @File: schemas.py
# @Project: sk-server
# Software: PyCharm
from pydantic import BaseModel


class AuthModel(BaseModel):
    username: str
    password: str


class BaseResponse(BaseModel):
    state: str = 'ok'
    message: str
    data: dict = {}
