from pyramid.config import Configurator
from pyramid.authentication import SessionAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.session import UnencryptedCookieSessionFactoryConfig

from sqlalchemy import engine_from_config
from sqlalchemy.orm import sessionmaker

from .models import RootFactory
import views


def add_params(f, *args, **kwargs):
    def add_matchdict(request, *args, **kwargs):
        kwargs.update(request.matchdict)
        return f(request, *args, **kwargs)
    return add_matchdict

def add_session(f):
    def sess(request, *args, **kwargs):
        session = request.registry.dbmaker()
        def cleanup(request):
            if request.exception is not None:
                session.rollback()
            else:
                session.commit()
            session.close()
        request.add_finished_callback(cleanup)
        return f(request, session, *args, **kwargs)
    return sess


def create_routes(config, routes, sessioned=False, paramed=False):
    for name, route, perms, renderer in routes:
        config.add_route(name, route)
        view = getattr(views, name)
        if paramed:
            view = add_params(view)
        if sessioned:
            view = add_session(view)
        config.add_view(view, route_name=name, renderer=renderer, permission=perms)


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    authn_policy = SessionAuthenticationPolicy()
    authz_policy = ACLAuthorizationPolicy()
    session_factory = UnencryptedCookieSessionFactoryConfig(settings['session.secret'])
    engine = engine_from_config(settings, prefix='sqlalchemy.')
    config = Configurator(settings=settings,
                          root_factory=RootFactory,
                          authentication_policy=authn_policy,
                          authorization_policy=authz_policy,
                          session_factory=session_factory
                         )

    config.registry.current_resume = settings['current_resume']
    config.registry.dbmaker = sessionmaker(bind=engine)


    config.include('pyramid_chameleon')
    config.add_static_view('static', 'static', cache_max_age=3600)

    # no fanciness for these. Don't even need to hit the db
    basic_routes = [('home', '/', 'view', 'templates/home.pt'),
                    ('resume', '/resume', 'view', None),
                    ('logout', '/logout', 'view', 'templates/logout.pt'),
                   ]

    create_routes(config, basic_routes)

    # these dealies have a bit more going on. it's convenient to have the session and parms
    # readily available. cuts down the boilerplate significantly i find
    # tuples are (name, route, permissions). name is used for route_name, view_name and renderer
    fancy_routes = [('user', '/users/{username}', 'post', 'templates/user.pt'),
                    ('register', '/register', 'view', 'templates/register.pt'),
                    ('login', '/login', 'view', 'templates/login.pt'),
                   ]

    create_routes(config, fancy_routes, paramed=True, sessioned=True)

    config.scan()
    return config.make_wsgi_app()
