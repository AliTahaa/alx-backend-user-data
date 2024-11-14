#!/usr/bin/env python3
""" Module of Authentication """
from flask import request
from typing import List, TypeVar
from os import getenv

# Define the TypeVar
UserType = TypeVar('User')


class Auth:
    """ manage the API auth """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Method for validating """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True

        l_p = len(path)
        if l_p == 0:
            return True

        s_path = True if path[l_p - 1] == '/' else False

        tmp_p = path
        if not s_path:
            tmp_p += '/'

        for exc in excluded_paths:
            l_e = len(exc)
            if l_e == 0:
                continue

            if exc[l_e - 1] != '*':
                if tmp_p == exc:
                    return False
            else:
                if exc[:-1] == path[:l_e - 1]:
                    return False

        return True

    def authorization_header(self, request=None) -> str:
        """ handles auth header """
        if request is None:
            return None

        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> UserType:
        """ Validates current user """
        return None

    def session_cookie(self, request=None):
        """ Returns a cookie value """

        if request is None:
            return None

        SESSION_NAME = getenv("SESSION_NAME")

        if SESSION_NAME is None:
            return None

        session_id = request.cookies.get(SESSION_NAME)

        return session_id
