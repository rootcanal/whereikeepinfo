import os
import tempfile
import time
import mimetypes
import logging

from pyramid.response import FileResponse
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config
from pyramid.view import view_defaults

import utils
from whereikeepinfo import forms
from whereikeepinfo.models import File
from whereikeepinfo.models import User
from whereikeepinfo.views.base import LoggedInView
from whereikeepinfo.views import utils


logger = logging.getLogger(__name__)


@view_defaults(route_name='view_files', renderer='whereikeepinfo:templates/files.pt')
class FilesView(LoggedInView):

    @view_config(request_method='POST')
    def upload_file(self):
        self.require_key()
        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(User.username==self.username).first()

            if 'uploaded_file' in self.request.POST and form.validate():
                f = form.data['uploaded_file']
                name = f['filename']
                size = f['size']
                self.request.session.flash(u'successfully uploaded file %s.' % (name, ))
                pubs = []
                for key in user.keys:
                    pubs.append(key.public_key)
                encrypted = utils.encrypt(f['file'], pubs)
                name = utils.store_file(encrypted, name, user.username, self.storage_dir)
                fileobj = File(name, size, user.id)
                fileobj.owner = user
                for key in user.keys:
                    fileobj.keys.append(key)
                user.files.append(fileobj)
                session.add(user)

        return HTTPFound(location=self.request.route_url('view_files'))

    @view_config(request_method='GET')
    def view_files(self):
        self.require_verification()
        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(User.username==self.username).first()
            current_upload_size = sum([f.size for f in user.files])
            username = user.username
            owned_files = dict()
            shared_files = dict()
            for f in user.files:
                shared_with = [k.user.username for k in f.keys]
                owned_file = dict(shared=shared_with, uploaded_at=f.uploaded_at, size=f.size)
                owned_files[f.name] = owned_file
                shared_files[f.name] = dict(size=f.size, owner=f.owner.username)
            sharable_users = session.query(User).filter(User.sharable==True)
            sharable_users = sharable_users.filter(User.username!=self.username).all()
            sharable_users = [u.username for u in sharable_users]

        return dict(
            current_upload_size=current_upload_size,
            username=username,
            uploaded_files=owned_files,
            sharable_users=sharable_users,
            shared_files=shared_files
        )


    @view_config(route_name="manage_file", renderer='whereikeepinfo:templates/manage_file.pt')
    def manage_file(self):
        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(User.username==self.username).first()
            f = session.query(File).filter(File.name==self.filename).first()
            username = user.username
            size = f.size
            uploaded_at = f.uploaded_at

            sharable_users = session.query(User).filter(User.sharable==True)
            sharable_users = sharable_users.filter(User.username!=self.username).all()
            sharable_users = [u.username for u in sharable_users]

            shared_with = ', '.join([k.user.username for k in f.keys])

        return dict(
            username=username,
            filename=self.filename,
            uploaded_at=uploaded_at,
            size=size,
            sharable_users=sharable_users,
            shared_with=shared_with
        )


    @view_config(route_name='view_file', renderer='whereikeepinfo:templates/view_file.pt')
    def view_file(self):
        if 'form.submitted' in self.request.POST and form.validate():
            with utils.db_session(self.dbmaker) as session:
                user = session.query(User).filter(User.username==self.username).first()
                f = session.query(File).filter(File.name==self.filename).first()
                proper_key = [k for k in f.keys if k.user.username == user.username]
                logger.info('owner: %s files: %s keys: %s', f.owner, user.files, f.keys)
                if f.owner != user.username and len(proper_key) == 0:
                    self.request.session.flash(u'File not shared with you. are you a bad actor?')
                    return HTTPFound(location=self.request.route_url('home'))
                privs = []
                pubs = []
                for k in proper_key:
                    privs.append(k.private_key)
                    pubs.append(k.public_key)
                query_file = os.path.join(self.storage_dir, f.owner.username, self.filename)
            if not os.path.isfile(query_file):
                return HTTPNotFound("file %s is not a thinger" % (self.filename, ))
            content_type, encoding = mimetypes.guess_type(query_file)
            with open(query_file, 'rb') as o:
                encrypted = o.read()
                decrypted = utils.decrypt(encrypted, privs, pubs, form.data['passphrase']) 
            with utils.tmpdir() as tmpd:
                tmp = os.path.join(tmpd, self.filename)
                with open(tmp, 'wb') as tmpf:
                    tmpf.write(decrypted)
                    tmpf.flush()
                    response = FileResponse(
                        tmp,
                        request=self.request,
                        content_type=content_type,
                        content_encoding=encoding
                    )
                    return response
        return dict(
            username=self.username,
            filename=self.filename
        )

    @view_config(route_name='delete_file')
    def delete_file(self):
        query_file = os.path.join(self.storage_dir, self.username, self.filename)
        with utils.db_session(self.dbmaker) as session:
            f = session.query(File).filter(File.name==self.filename).first()
            session.delete(f)
        os.remove(query_file)
        self.request.session.flash(u'successfully deleted file: %s.' % (self.filename, ))
        return HTTPFound(location=self.request.route_url('view_files'))

    @view_config(route_name='share_file', renderer='whereikeepinfo:templates/share_file.pt')
    def share_file(self):
        if 'form.submitted' in self.request.POST and form.validate():
            passphrase = form.data['passphrase']
            query_file = os.path.join(self.storage_dir, self.username, self.filename)
            share_user = self.request.params['share_user']
            with utils.db_session(self.dbmaker) as session:
                owner = session.query(User).filter(User.username==self.username).one()
                f = session.query(File).filter(File.name==self.filename).one()
                u = session.query(User).filter(User.username==share_user).first()
                if u is None:
                    del f.shared_users[:]
                else:
                    for key in u.keys:
                        f.keys.append(key)
                session.add(f)
                owner_pubs = [k.public_key for k in owner.keys]
                owner_privs = [k.private_key for k in owner.keys]
                recipients = owner_pubs + [k.public_key for k in f.keys]
                with open(query_file, 'rb') as o:
                    data = o.read()
                decrypted = utils.decrypt(data, owner_privs, owner_pubs, passwd)
                with tempfile.NamedTemporaryFile() as tmp:
                    tmp.write(decrypted)
                    tmp.flush()
                    tmp.seek(0)
                    encrypted = utils.encrypt(tmp, recipients)
                tmp = tempfile.NamedTemporaryFile(dir=self.storage_dir, delete=False)
                tmp.write(encrypted)
                os.rename(tmp.name, query_file)
            self.request.session.flash(
                u'successfully shared file: %s with user %s' % (self.filename, share_user)
            )
            return HTTPFound(location=self.request.route_url('view_files'))
        with utils.db_session(self.dbmaker) as session:
            sharable_users = session.query(User).filter(User.sharable==True)
            sharable_users = sharable_users.filter(User.username!=self.username).all()
            sharable_users = [u.username for u in sharable_users]
        return dict(
            username=self.username,
            filename=self.filename,
            sharable_users=sharable_users
        )

    @view_config(route_name='unshare_file')
    def unshare_file(self):
        query_file = os.path.join(self.storage_dir, self.username, self.filename)
        with utils.db_session(self.dbmaker) as session:
            f = session.query(File).filter(File.name==self.filename).first()
            u = session.query(User).filter(User.username==self.unshare_user).first()
            for key in u.keys:
                if key in f.keys:
                    f.keys.remove(key)
            session.add(f)
        self.request.session.flash(
            u'no longer sharing file: %s with user: %s' % (self.filename, self.unshare_user)
        )
        return HTTPFound(location=self.request.route_url('view_files'))
