#!/usr/bin/env python3
""" Encrypt password """
import bcrypt


def hash_password(password: str) -> bytes:
    """ Returns hashed password """
    encoded_pw = password.encode()
    hashed_pw = bcrypt.hashpw(encoded_pw, bcrypt.gensalt())

    return hashed_pw


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Validates the password """
    valid_flag = False
    encoded_pw = password.encode()
    if bcrypt.checkpw(encoded_pw, hashed_password):
        valid_flag = True
    return valid_flag
