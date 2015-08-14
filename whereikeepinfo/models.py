import time

from passlib.hash import bcrypt

import sqlalchemy as sa
import sqlalchemy.orm as sa_orm
from sqlalchemy.ext.declarative import declarative_base

from pyramid.security import Allow
from pyramid.security import Authenticated
from pyramid.security import Everyone

Base = declarative_base()


keys_files_map = sa.Table('keys_files_map', Base.metadata,
    sa.Column('key_id', sa.INTEGER, sa.ForeignKey('keys.id')),
    sa.Column('file_id', sa.INTEGER, sa.ForeignKey('files.id'))
)


class User(Base):

    __tablename__ = 'users'
    id = sa.Column(sa.INTEGER, primary_key=True)
    created_at = sa.Column(sa.INTEGER, nullable=False)
    username = sa.Column(sa.TEXT, unique=True, nullable=False)
    name = sa.Column(sa.TEXT, nullable=False)
    email = sa.Column(sa.TEXT, unique=True, nullable=False)
    verified_at = sa.Column(sa.INTEGER, nullable=True)
    sharable = sa.Column(sa.BOOLEAN, default=False, nullable=False)
    files = sa_orm.relationship('File', backref='owner')
    keys = sa_orm.relationship('Key', backref='user')

    _password = sa.Column('password', sa.TEXT, nullable=False)

    def _get_password(self):
        return self._password
    def _set_password(self, password):
        self._password = bcrypt.encrypt(password)

    password = property(_get_password, _set_password)
    password = sa_orm.synonym('_password', descriptor=password)

    def __init__(self, username, name, email, password, created_at):
        self.username = username
        self.name = name
        self.email = email
        self.password = password
        self.created_at = created_at


class File(Base):
    __tablename__ = 'files'
    id = sa.Column(sa.INTEGER, primary_key=True)
    uploaded_at = sa.Column(sa.INTEGER, nullable=False)
    name = sa.Column(sa.TEXT, unique=True)
    size = sa.Column(sa.INTEGER, nullable=False)
    user_id = sa.Column(sa.INTEGER, sa.ForeignKey('users.id'))
    keys = sa_orm.relationship('Key', secondary=keys_files_map, backref='files')

    def __init__(self, name, size, user_id):
        self.name = name
        self.size = size
        self.user_id = user_id
        self.uploaded_at = time.time()


class Key(Base):
    __tablename__ = 'keys'
    id = sa.Column(sa.INTEGER, primary_key=True)
    name = sa.Column(sa.TEXT, nullable=False)
    created_at = sa.Column(sa.INTEGER)
    public_key = sa.Column('public_key', sa.TEXT)
    private_key = sa.Column('private_key', sa.TEXT)
    user_id = sa.Column(sa.INTEGER, sa.ForeignKey('users.id'))

    def __init__(self, name, userid, pub, priv):
        self.name = name
        self.user_id = userid
        self.public_key = pub
        self.private_key = priv
        self.created_at = time.time()
