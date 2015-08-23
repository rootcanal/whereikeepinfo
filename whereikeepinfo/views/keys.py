import time
import base64
import mimetypes
import os
import logging

from pyramid.response import FileResponse
from pyramid.view import view_config
from pyramid.view import view_defaults
from pyramid.security import remember
from pyramid.security import forget
from pyramid.httpexceptions import HTTPFound

from whereikeepinfo.models import User
from whereikeepinfo.models import Key
from whereikeepinfo.views.base import LoggedInView
from whereikeepinfo.views import utils
from whereikeepinfo import forms


logger = logging.getLogger(__name__)


@view_defaults(route_name='keys', renderer='whereikeepinfo:templates/manage_keys.pt')
class KeyView(LoggedInView):

    @view_config(request_method='POST')
    def genkey(self):
        self.require_verification()
        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(User.username==self.username).first()

            if form.validate():
                name = form.data['keyname']
                passphrase = form.data['passphrase']
                pub, priv = utils.keygen(name, user.email, passphrase)
                keyobj = Key(name, user.id, pub, priv)
                user.keys.append(keyobj)
                session.add(keyobj)
                session.add(user)
                self.request.session.flash(u'successfully generated key %s.' % (name, ))

        return HTTPFound(location=self.request.route_url('keys'))

    @view_config(request_method='GET')
    def view_keys(self):
        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(User.username==self.username).first()
            keys = dict()
            for key in user.keys:
                keys[key.name] = dict(created_at=key.created_at)

        return dict(
            keys=keys,
            username=self.username
        )

    @view_config(route_name='export_key', renderer='whereikeepinfo:templates/export_key.pt')
    def export_key(self):
        self.require_verification()
        if 'form.submitted' in self.request.POST and form.validate():
            with utils.db_session(self.dbmaker) as session:
                user = session.query(User).filter(User.username==self.username).first()
                key = session.query(Key).filter(Key.user_id==user.id, Key.name==self.key).first()
                pub = base64.b64decode(key.public_key)
                priv = base64.b64decode(key.private_key)
                priv = utils.decrypt(priv, pub, pub, form.data['passphrase'])
                filename = user.username + '.keypair.asc'
            content_type, encoding = mimetypes.guess_type(filename)
            logger.info('priv: %s', priv)
            with utils.tmpdir() as tmpd:
                tmp = os.path.join(tmpd, filename)
                with open(tmp, 'wb') as tmpf:
                    tmpf.write('\n\n'.join((pub, priv)))
                    tmpf.flush()
                    response = FileResponse(
                        tmp,
                        request=self.request
                    )
                    return response
        return dict(
            username=self.username,
            key=self.key
        )

    @view_config(route_name='delete_key')
    def delete_key(self):
        self.require_verification()
        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(User.username==self.username).first()
            key = session.query(Key).filter(Key.user_id==user.id, Key.name==self.key).first()
            session.delete(key)
        self.request.session.flash(u'successfully deleted key %s.' % (self.key, ))
        return HTTPFound(location=self.request.route_url('keys'))
