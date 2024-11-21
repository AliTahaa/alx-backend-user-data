#!/usr/bin/env python3
""" Authentication """
import bcrypt
from db import DB
from user import User
from uuid import uuid4
from sqlalchemy.orm.exc import NoResultFound


class Auth:
    """ Auth class """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ new user
            Args:
                - email
                - password
            Return:
                - User instance
        """
        dbase = self._db
        try:
            user = dbase.find_user_by(email=email)
        except NoResultFound:
            user = dbase.add_user(email, _hash_password(password))
            return user
        else:
            raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """ Checks password
            Args:
                - email
                - password
            Return:
                - True if credentials are valid
        """
        dbase = self._db
        try:
            user = dbase.find_user_by(email=email)
        except NoResultFound:
            return False
        if not bcrypt.checkpw(password.encode('utf-8'), user.hashed_password):
            return False
        return True

    def create_session(self, email: str) -> str:
        """ Creates session
            Args:
                - email
            Return:
                - session_id
        """
        dbase = self._db
        try:
            u = dbase.find_user_by(email=email)
        except NoResultFound:
            return None
        s_id = _generate_uuid()
        dbase.update_user(u.id, session_id=s_id)
        return s_id

    def get_user_from_session_id(self, s_id: str) -> User:
        """ Gets user based on their session id
            Args:
                - session_id
            Return:
                - User if found
        """
        if not s_id:
            return None
        dbase = self._db
        try:
            user = dbase.find_user_by(session_id=s_id)
        except NoResultFound:
            return None
        return user

    def destroy_session(self, user_id: int) -> None:
        """ Destroys session """
        dbase = self._db
        dbase.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """ Generates reset password token for valid user
            Args:
                - email
            Return:
                - reset password
        """
        dbase = self._db
        try:
            user = dbase.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        reset_token = _generate_uuid()
        dbase.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """ Update password for user with matching reset token
            Args:
                - reset_toke: user's reset token
                - password: new password
            Return:
                - None
        """
        db = self._db
        try:
            user = db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        db.update_user(user.id, hashed_password=_hash_password(password),
                       reset_token=None)


def _hash_password(password: str) -> bytes:
    """ Creates password hash
        Args:
            - password: user password
        Return:
            - hashed password
    """
    e_pwd = password.encode()
    return bcrypt.hashpw(e_pwd, bcrypt.gensalt())


def _generate_uuid() -> str:
    """ Generates unique ids
        Return:
            - UUID generated
    """
    return str(uuid4())
