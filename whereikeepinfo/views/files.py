import os
import time
import mimetypes

from pyramid.response import FileResponse
from pyramid_simpleform.renderers import FormRenderer
from pyramid_simpleform import Form
from pyramid.httpexceptions import HTTPFound
from pyramid.httpexceptions import HTTPNotFound
from pyramid.view import view_config
from pyramid.view import view_defaults

import utils
from whereikeepinfo import forms
from whereikeepinfo.models import File
from whereikeepinfo.models import User
from whereikeepinfo.views.base import BaseView
from whereikeepinfo.views import utils


@view_defaults(route_name='files', renderer='whereikeepinfo:templates/file.pt')
class FilesView(BaseView):

    @view_config(request_method='POST')
    def upload_file(self):
        if self.username is None:
            self.request.session.flash(u'You must be logged in to keep files.')
            return HTTPFound(location=self.request.route_url('login'))

        form = Form(self.request, schema=forms.UploadFileSchema)

        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(User.username==self.username).first()

            if 'uploaded_file' in self.request.POST and form.validate():
                f = form.data['uploaded_file']
                name = f['filename']
                size = f['size']
                self.request.session.flash(u'successfully uploaded file %s.' % (name, ))
                name = utils.store_file(f['file'], name, user.username, self.storage_dir)
                fileobj = File(name, size, user.id)
                user.files.append(fileobj)
                session.add(user)

        return HTTPFound(location=self.request.route_url('files'))

    @view_config(request_method='GET')
    def view_files(self):
        if self.username is None:
            self.request.session.flash(u'You must be logged in to keep files.')
            return HTTPFound(location=self.request.route_url('login'))

        form = Form(self.request, schema=forms.UploadFileSchema)

        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(User.username==self.username).first()
            current_upload_size = sum([f.size for f in user.files])
            username = user.username
            files = [f.name for f in user.files]

        return dict(
            current_upload_size=current_upload_size,
            form=FormRenderer(form),
            username=username,
            uploaded_files=files
        )


    @view_config(route_name='file')
    def view_file(self):
        if self.username is None:
            self.request.session.flash(u'You must be logged in to view files.')
            return HTTPFound(location=self.request.route_url('login'))
        query_file = os.path.join(self.storage_dir, self.username, self.filename)
        if not os.path.isfile(query_file):
            return HTTPNotFound("file %s is not a thinger" % (self.filename, ))
        if 'delete' in self.__dict__ and self.delete:
            with utils.db_session(self.dbmaker) as session:
                f = session.query(File).filter(File.name==self.filename).first()
                session.delete(f)
            os.remove(query_file)
            self.request.session.flash(u'successfully deleted file: %s.' % (self.filename, ))
            response = HTTPFound(location=self.request.route_url('files'))
        else:
            content_type, encoding = mimetypes.guess_type(query_file)
            response = FileResponse(
                query_file,
                request=self.request,
                content_type=content_type,
                content_encoding=encoding
            )
        return response
