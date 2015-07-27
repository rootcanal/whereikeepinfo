import logging

from pyramid.config import Configurator
from pyramid.authentication import SessionAuthenticationPolicy
from pyramid.authorization import ACLAuthorizationPolicy
from pyramid.session import UnencryptedCookieSessionFactoryConfig

from sqlalchemy import engine_from_config
from sqlalchemy.orm import sessionmaker

from .models import RootFactory
import views


logger = logging.getLogger(__name__)


def create_routes(config, routes):
    for name, route in routes:
        logger.info('adding route: %s', name)
        config.add_route(name, route)


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    logging.basicConfig(level=logging.DEBUG)

    authn_policy = SessionAuthenticationPolicy()
    authz_policy = ACLAuthorizationPolicy()
    session_factory = UnencryptedCookieSessionFactoryConfig(settings['session.secret'])
    config = Configurator(settings=settings,
                          root_factory=RootFactory,
                          authentication_policy=authn_policy,
                          authorization_policy=authz_policy,
                          session_factory=session_factory
                         )

    # our session maker object to be set up on request
    engine = engine_from_config(settings, prefix='sqlalchemy.')
    config.registry.settings['dbmaker'] = sessionmaker(bind=engine)

    config.include('pyramid_chameleon')
    config.add_static_view('static', 'static', cache_max_age=3600)

    routes = [('resume', '/about/resume'),
              ('logout', '/logout'),
              ('home', '/'),
              ('view_files', '/files'),
              ('view_file', '/files/view/{filename}'), 
              ('manage_file', '/files/manage/{filename}'), 
              ('delete_file', '/files/delete/{filename}'), 
              ('share_file', '/files/share/{filename}'), 
              ('unshare_file', '/files/unshare/{filename}/{unshare_user}'), 
              ('user', '/users/{userid}'),
              ('toggle_sharability', '/users/{userid}/toggle_sharability'),
              ('register', '/register'),
              ('verify', '/verify/{token}'),
              ('send_verify', '/verify'),
              ('login', '/login'),
              ('about', '/about')
             ]

    create_routes(config, routes)

    config.scan()
    return config.make_wsgi_app()
