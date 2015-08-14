import smtplib
import time
import logging

from pyramid_simpleform.renderers import FormRenderer
from pyramid_simpleform import Form
from pyramid.view import view_config
from pyramid.view import view_defaults
from pyramid.security import remember
from pyramid.security import forget
from pyramid.httpexceptions import HTTPFound
from itsdangerous import URLSafeTimedSerializer

from whereikeepinfo.models import User
from whereikeepinfo.views.base import BaseView
from whereikeepinfo.views import utils
from whereikeepinfo import forms


logger = logging.getLogger(__name__)


@view_defaults(route_name='auth')
class AuthView(BaseView):

    @view_config(route_name='send_verify')
    def send_verify(self):
        self.require_login()
        with utils.db_session(self.dbmaker) as session:
            email = session.query(User.email).filter(User.username==self.username).first()
        serializer = URLSafeTimedSerializer(self.verification_key)
        token = serializer.dumps(email, salt=self.verification_salt)
        token_url = self.request.route_url('verify', token=token)
    
        server = smtplib.SMTP(self.email_server, self.email_port)
        server.ehlo()
        server.starttls()
        server.login(self.email_user, self.email_password)
        body = '\r\n'.join(['To: %s' % (email, ),
                            'From: %s' % (self.email_user, ),
                            'Subject: %s' % ('Thanks for registering at whereikeep.info', ),
                            '',
                            'Click here to complete registration %s' % (token_url, )
                           ])
        server.sendmail(self.email_user, [email], body)
        self.request.session.flash(u'Registration email sent. '\
            'Follow instructions in email to complete registration')
        return HTTPFound(location=self.request.route_url('home'))

    @view_config(route_name='register', renderer='whereikeepinfo:templates/register.pt')
    def register(self):
        form = Form(self.request, schema=forms.RegistrationSchema)
    
        if 'form.submitted' in self.request.POST and form.validate():
            username = form.data['username']
            user = User(
                username=username,
                password=form.data['password'],
                name=form.data['name'],
                email=form.data['email'],
                created_at=time.time()
            )
            with utils.db_session(self.dbmaker) as session:
                session.add(user)
            headers = remember(self.request, username)
            return HTTPFound(location=self.request.route_url('send_verify'), headers=headers)
    
        return dict(
            form=FormRenderer(form),
            username=self.username
        )

    @view_config(route_name='verify', renderer='whereikeepinfo:templates/verify.pt')
    def verify(self):
        email = utils.verify_email(self.token, self.verification_key, self.verification_salt)
        if not email:
            self.request.session.flash(u'Unable to verify your email account')
            return HTTPFound(location=self.request.route_url('home'))
        form = Form(self.request, schema=forms.LoginSchema)
        if 'form.submitted' in self.request.POST:
            if not utils.authenticate_user(form, self.dbmaker):
                self.request.session.flash(u'Failed to verify your account credentials')
                return HTTPFound(location=self.request.route_url('home'))
            headers = remember(self.request, self.username)
            with utils.db_session(self.dbmaker) as session:
                user = session.query(User).filter(User.email==email).first()
                (pub, priv) = utils.keygen(user.name, user.email, form.data['password'])
                user.verified_at = time.time()
                session.add(user)
                self.request.session.flash(u'Account verified!')
                return HTTPFound(location=self.request.route_url('keys'))
        return dict(
            form=FormRenderer(form),
            username=self.username,
            token=self.token
        )

    @view_config(route_name='user', renderer='whereikeepinfo:templates/user.pt')
    def user(self):
        self.require_login()
        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(User.username==self.username).first()
            return dict(
                name=user.name,
                username=user.username,
                email=user.email,
                created_at=user.created_at,
                verified=user.verified_at is not None,
                sharable=user.sharable,
                filecount=len(user.files)
            )

    @view_config(route_name='toggle_sharability')
    def toggle_sharability(self):
        self.require_login()
        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(User.username==self.username).first()
            user.sharable = not user.sharable
            session.add(user)
        return HTTPFound(location=self.request.route_url('user', userid=self.username))

    @view_config(route_name='login', renderer='whereikeepinfo:templates/login.pt')
    def login(self):
        came_from = self.request.params.get('came_from', self.request.route_url('home'))
        form = Form(self.request, schema=forms.LoginSchema)
        if 'form.submitted' in self.request.POST:
            if utils.authenticate_user(form, self.dbmaker):
                headers = remember(self.request, form.data['username'])
                self.request.session.flash(u'Logged in successfully.')
                return HTTPFound(location=came_from, headers=headers)
            self.request.session.flash(u'Failed to login.')
            return HTTPFound(location=came_from)
        return dict(
            form=FormRenderer(form),
            username=self.username,
            came_from=came_from
        )

    @view_config(route_name='logout')
    def logout(self):
        self.request.session.invalidate()
        self.request.session.flash(u'Logged out successfully.')
        headers = forget(self.request)
        return HTTPFound(location=self.request.route_url('home'), headers=headers)
