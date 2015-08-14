from pyramid.httpexceptions import HTTPFound
from pyramid.security import authenticated_userid


class BaseView(object):
    def __init__(self, request):
        self.request = request
        self.username = authenticated_userid(request)
        self.__dict__.update(request.matchdict)
        self.__dict__.update(request.registry.settings)

    def require_login(self, errmsg=u'you must be logged in to do that', came_from='home'):
        if self.username is None:
            self.request.session.flash(errmsg)
            raise HTTPFound(location=self.request.route_url('login', came_from=came_from))

class LoggedInView(BaseView):

    def __init__(self, request):
        super(LoggedInView, self).__init__(request)
        self.require_login()
