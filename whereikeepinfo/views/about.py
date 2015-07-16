import mimetypes

from pyramid.response import FileResponse
from pyramid.view import view_defaults
from pyramid.view import view_config

from whereikeepinfo.views.base import BaseView


class AboutView(BaseView):

    @view_config(route_name='resume')
    def resume(self):
        content_type, encoding = mimetypes.guess_type(self.current_resume)
        response = FileResponse(
            self.current_resume,
            request=self.request,
            content_type=content_type,
            content_encoding=encoding
        )
        return response

    @view_config(route_name='home', renderer='whereikeepinfo:templates/home.pt')
    def home(self):
        return dict(
           username=self.username
        )

    @view_config(route_name='about', renderer='whereikeepinfo:templates/about.pt')
    def about(self):
        return dict(
            username=self.username
        )
