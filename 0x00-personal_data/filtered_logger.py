#!/usr/bin/env python3
""" handle Personal Data """
from typing import List
import re
import logging
from os import environ
import mysql.connector


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """ Returns message """
    for i in fields:
        message = re.sub(f'{i}=.*?{separator}',
                         f'{i}={redaction}{separator}', message)
    return message


def get_logger() -> logging.Logger:
    """ Returns a Logger """
    user_data_logger = logging.getLogger("user_data")
    user_data_logger.setLevel(logging.INFO)
    user_data_logger.propagate = False

    info_stream_handler = logging.StreamHandler()
    info_stream_handler.setFormatter(RedactingFormatter(list(PII_FIELDS)))
    user_data_logger.addHandler(info_stream_handler)

    return user_data_logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ Returns a connector """
    db_username = environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    db_password = environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    db_host = environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = environ.get("PERSONAL_DATA_DB_NAME")

    db_conn = mysql.connector.connection.MySQLConnection(user=db_username,
                                                         password=db_password,
                                                         host=db_host,
                                                         database=db_name)

    return db_conn


def main():
    """ display each row filtered """
    database_connection = get_db()
    cursor = database_connection.cursor()
    cursor.execute("SELECT * FROM users;")
    user_field_names = [i[0] for i in cursor.description]

    logger = get_logger()

    for r in cursor:
        str_row = ''.join(f'{f}={str(r)}; ' for r, f in zip(r, user_field_names))
        logger.info(str_row.strip())

    cursor.close()
    database_connection.close()


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Filters values """
        record.msg = filter_datum(self.fields, self.REDACTION,
                                  record.getMessage(), self.SEPARATOR)
        return super(RedactingFormatter, self).format(record)


if __name__ == '__main__':
    main()
