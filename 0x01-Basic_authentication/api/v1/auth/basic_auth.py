#!/usr/bin/env python3
"""Basic authentication module for the API.
"""
import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User

# Define the TypeVar
UserType = TypeVar('User')


class BasicAuth(Auth):
    """ Basic authentication """
    def extract_base64_authorization_header(
            self,
            authorization_header: str) -> str:
        """Extracts the Base64 part """
        if type(authorization_header) is str:
            patt = r'Basic (?P<token>.+)'
            f_match = re.fullmatch(patt, authorization_header.strip())
            if f_match is not None:
                return f_match.group('token')
        return None

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str,
            ) -> str:
        """Decodes a base64-encoded """
        if type(base64_authorization_header) is str:
            try:
                res = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str,
            ) -> Tuple[str, str]:
        """Extracts user credentials """
        if type(decoded_base64_authorization_header) is str:
            patt = r'(?P<user>[^:]+):(?P<password>.+)'
            f_match = re.fullmatch(
                patt,
                decoded_base64_authorization_header.strip(),
            )
            if f_match is not None:
                user = f_match.group('user')
                password = f_match.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> UserType:
        """Retrieves a user based """
        if type(user_email) is str and type(user_pwd) is str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> UserType:
        """Retrieves the user """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
