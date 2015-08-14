from contextlib import contextmanager
import base64
import shutil
import tempfile
import os
import logging

import gnupg
from passlib.hash import bcrypt
from itsdangerous import URLSafeTimedSerializer
from pyramid_simpleform import Form
from pyramid.security import authenticated_userid

from whereikeepinfo.models import User


logger = logging.getLogger(__name__)


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
def tmpdir():
    tmp = tempfile.mkdtemp()
    try:
        yield tmp
    finally:
        shutil.rmtree(tmp)

@contextmanager
def gpg_session():
    with tmpdir() as tmp:
        try:
            gpg = gnupg.GPG(gnupghome=tmp)
            yield gpg
        finally:
            del gpg


def store_file(data, name, username, root_dir):
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
    with open(outf, 'wb') as o:
        o.write(data)
    return name

def authenticate_user(form, dbmaker):
        if form.validate():
            username = form.data['username']
            password = form.data['password']
            with db_session(dbmaker) as session:
                user = session.query(User).filter(User.username==username).first()
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


def keygen(name, email, passphrase):
    with gpg_session() as gpg:
        params = dict(name_real=name, name_email=email, passphrase=passphrase)
        input_data = gpg.gen_key_input(**params)
        key = gpg.gen_key(input_data)
        pub = base64.b64encode(gpg.export_keys(key.fingerprint))
        priv = base64.b64encode(gpg.export_keys(key.fingerprint, True))
    return (pub, priv)


def encrypt(f, key_or_keys):
    if isinstance(key_or_keys, basestring):
        key_or_keys = [key_or_keys]
    keys = '\n'.join([base64.b64decode(k) for k in key_or_keys])
    with gpg_session() as gpg:
        imported_keys = gpg.import_keys(keys)
        recipients = imported_keys.fingerprints
        logger.info('recipients: %s', recipients)
        return str(gpg.encrypt_file(f, recipients, always_trust=True))


def decrypt(data, private_key, public_key, passphrase):
    with gpg_session() as gpg:
        decoded_key = base64.b64decode(private_key)
        gpg.import_keys(decoded_key)
        gpg.import_keys(base64.b64decode(public_key))
        return str(gpg.decrypt(data, passphrase=passphrase, always_trust=True))
