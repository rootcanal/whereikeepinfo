from contextlib import contextmanager
import base64
import shutil
import tempfile
import os

import gnupg
from Crypto.Cipher import AES
from passlib.hash import bcrypt
from itsdangerous import URLSafeTimedSerializer
from pyramid_simpleform import Form
from pyramid.security import authenticated_userid

from whereikeepinfo.models import User


@contextmanager
def db_session(sessionmaker):
    session = sessionmaker()
    try:
        yield session
    except Exception as e:
        session.rollback()
        raise e
    else:
        session.commit()
    session.close()

@contextmanager
def gpg_session():
    tmp = tempfile.mkdtemp()
    try:
        gpg = gnupg.GPG(gnupghome=tmp)
        yield gpg
    finally:
        del gpg
        shutil.rmtree(tmp)


def store_file(f, name, username, root_dir):
    userdir = os.path.join(root_dir, username)
    if not os.path.isdir(userdir):
        os.makedirs(userdir)
    if os.path.exists(os.path.join(userdir, name)):
        i = 0
        while True:
            i += 1
            new_name = "(%d)-%s" % (i, name)
            if not os.path.exists(os.path.join(userdir, new_name)):
                name = new_name
                break
    outf = os.path.join(userdir, name)
    print 'writing file:',  outf
    with open(outf, 'wb') as o:
        o.write(f.read())
    return name


def get_user_by_name(request, session):
    userid = authenticated_userid(request)
    print 'userid:', userid
    if userid is not None:
        return session.query(User).filter(User.username==userid).first()

def authenticate_user(form, request, dbmaker):
        if form.validate():
            username = form.data['username']
            password = form.data['password']
            with db_session(dbmaker) as session:
                user = session.query(User).filter(User.username==username).one()
                if user and bcrypt.verify(password, user.password):
                    return True
        return False

def verify_email(token, key, salt, max_age=3600):
    serializer = URLSafeTimedSerializer(key)
    try:
        email = serializer.loads(
            token,
            salt=salt,
            max_age=max_age
        )['email']
    except Exception as e:
        return False
    return email


def pad(passphrase, bs=32, padder='x'):
    return passphrase + (bs - len(passphrase) % bs) * padder


def keygen(user, passphrase):
    cipher = AES.new(pad(passphrase))
    with gpg_session() as gpg:
        params = dict(name_real=user.name, name_email=user.email, passphrase=passphrase)
        input_data = gpg.gen_key_input(**params)
        key = gpg.gen_key(input_data)
        pub = base64.b64encode(gpg.export_keys(key.fingerprint))
        priv = base64.b64encode(cipher.encrypt(pad(gpg.export_keys(key.fingerprint, True))))
    return (pub, priv)
