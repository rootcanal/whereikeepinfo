import cryptacular.bcrypt

import sqlalchemy as sa
import sqlalchemy.orm as sa_orm
from sqlalchemy.ext.declarative import declarative_base

from pyramid.security import Allow
from pyramid.security import Authenticated
from pyramid.security import Everyone

Base = declarative_base()
crypt = cryptacular.bcrypt.BCRYPTPasswordManager()


class User(Base):

    __tablename__ = 'users'
    id = sa.Column(sa.INTEGER, primary_key=True)
    username = sa.Column(sa.TEXT, unique=True, nullable=False)
    name = sa.Column(sa.TEXT, nullable=False)
    email = sa.Column(sa.TEXT, nullable=False)
    last_probe = sa.Column(sa.INTEGER)

    _password = sa.Column('password', sa.TEXT, nullable=False)

    def _get_password(self):
        return self._password
    def _set_password(self, password):
        self._password = crypt.encode(password)

    password = property(_get_password, _set_password)
    password = sa_orm.synonym('_password', descriptor=password)

    def __init__(self, username, name, email, password):
        self.username = username
        self.name = name
        self.email = email
        self.password = password


class RootFactory(object):
    __acl__ = [
        (Allow, Everyone, 'view'),
        (Allow, Authenticated, 'post')
    ]

    def __init__(self, request):
        pass  # pragma: no cover
