from contextlib import contextmanager
import os

from pyramid.security import authenticated_userid


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
