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


def update_registry(config, settings):
    config.registry.current_resume = settings['current_resume']

    # itsdangerous-specific key and salt for serializing verification links
    config.registry.verification_key = settings['verification_key']
    config.registry.verification_salt = settings['verification_salt']

    # all the bits for actually sending out the verification emails
    config.registry.email_user = settings['email_user']
    config.registry.email_password = settings['email_password']
    config.registry.email_server = settings['email_server']
    config.registry.email_port = settings['email_port']

    # our session maker object to be set up on request
    engine = engine_from_config(settings, prefix='sqlalchemy.')
    config.registry.dbmaker = sessionmaker(bind=engine)


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    authn_policy = SessionAuthenticationPolicy()
    authz_policy = ACLAuthorizationPolicy()
    session_factory = UnencryptedCookieSessionFactoryConfig(settings['session.secret'])
    config = Configurator(settings=settings,
                          root_factory=RootFactory,
                          authentication_policy=authn_policy,
                          authorization_policy=authz_policy,
                          session_factory=session_factory
                         )

    update_registry(config, settings)

    config.include('pyramid_chameleon')
    config.add_static_view('static', 'static', cache_max_age=3600)

    # no fanciness for these. Don't even need to hit the db
    basic_routes = [('resume', '/resume', 'view', None),
                    ('logout', '/logout', 'view', 'templates/logout.pt'),
                   ]

    create_routes(config, basic_routes)

    # these dealies have a bit more going on. it's convenient to have the session and parms
    # readily available. cuts down the boilerplate significantly i find
    # tuples are (name, route, permissions, template). name is used for route_name, view_name and renderer
    fancy_routes = [('home', '/', 'view', 'templates/home.pt'),
                    ('user', '/users/{username}', 'post', 'templates/user.pt'),
                    ('register', '/register', 'view', 'templates/register.pt'),
                    ('verify', '/verify/{token}', 'view', 'templates/verify.pt'),
                    ('login', '/login', 'view', 'templates/login.pt'),
                   ]

    create_routes(config, fancy_routes, paramed=True, sessioned=True)

    config.scan()
    return config.make_wsgi_app()
