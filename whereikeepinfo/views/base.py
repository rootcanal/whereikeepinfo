from pyramid.security import authenticated_userid

class BaseView(object):
    def __init__(self, request):
        self.request = request
        self.username = authenticated_userid(request)
        self.__dict__.update(request.matchdict)
        self.__dict__.update(request.params)
        self.__dict__.update(request.registry.settings)
