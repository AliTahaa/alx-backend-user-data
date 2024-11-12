#!/usr/bin/env python3
""" Module of Authentication """
from flask import request
from typing import List, TypeVar

# Define the TypeVar
UserType = TypeVar('User')


class Auth:
    """ Class to manage the API """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Method for validating """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True

        l_p = len(path)
        if l_p == 0:
            return True

        s_p = True if path[l_p - 1] == '/' else False

        t_p = path
        if not s_p:
            t_p += '/'

        for exc in excluded_paths:
            l_exc = len(exc)
            if l_exc == 0:
                continue

            if exc[l_exc - 1] != '*':
                if t_p == exc:
                    return False
            else:
                if exc[:-1] == path[:l_exc - 1]:
                    return False

        return True

    def authorization_header(self, request=None) -> str:
        """ Method that handles authorization """
        if request is None:
            return None

        return request.headers.get("Authorization", None)

    def current_user(self, request=None) -> UserType:
        """ Validates current user """
        return None
