import smtplib

from passlib.hash import bcrypt
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


@view_defaults(route_name='auth')
class AuthView(BaseView):

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
    
            serializer = URLSafeTimedSerializer(self.verification_key)
            token = serializer.dumps(form.data['email'], salt=self.verification_salt)
            token_url = self.request.route_url('verify', token=token)
    
            server = smtplib.SMTP(self.email_server, self.email_port)
            server.ehlo()
            server.starttls()
            server.login(self.email_user, self.email_password)
            body = '\r\n'.join(['To: %s' % (form.data['email'], ),
                                'From: %s' % (self.email_user, ),
                                'Subject: %s' % ('Thanks for registering at whereikeep.info', ),
                                '',
                                'Click here to complete registration %s' % (token_url, )
                               ])
            server.sendmail(self.email_user, [form.data['email']], body)
    
            headers = remember(self.request, username)
    
            redirect_url = self.request.route_url('home')
    
            self.request.session.flash(u'Registration email sent. '\
                'Follow instructions in email to complete registration')
    
            return HTTPFound(location=redirect_url, headers=headers)
    
        return dict(
            form=FormRenderer(form),
            username=self.username
        )

    @view_config(route_name='verify')
    def verify(self):

        serializer = URLSafeTimedSerializer(self.verification_key)
        try:
            email = serializer.loads(
                token,
                salt=self.verification_salt,
                max_age=3600
            )
        except:
            self.request.session.flash(u'Unable to verify your account. sry...')
        self.request.session.flash(u'Account verified!')

        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(email==email).first()
            user.verified = True
            user.verified_at = time.time()
            session.add(user)
    
            headers = remember(self.request, user.username)
    
            return dict(username=user.username, user=user)

    @view_config(route_name='user', renderer='whereikeepinfo:templates/user.pt')
    def user(self):
        with utils.db_session(self.dbmaker) as session:
            user = session.query(User).filter(User.username==self.username).first()
            return dict(
                name=user.name,
                username=user.username,
                email=user.email,
                created_at=user.created_at,
                verified_at=user.verified_at
            )

    @view_config(route_name='login', renderer='whereikeepinfo:templates/login.pt')
    def login(self):
        form = Form(self.request, schema=forms.LoginSchema)
        if 'form.submitted' in self.request.POST and form.validate():
            username = form.data['username']
            password = form.data['password']

            came_from = self.request.url 
            if came_from == self.request.route_url('login'):
                came_from = self.request.route_url('home')

            with utils.db_session(self.dbmaker) as session:
                user = session.query(User).filter(User.username==username).first()

                if user and bcrypt.verify(password, user.password):
                    headers = remember(self.request, username)
                    self.request.session.flash(u'Logged in successfully.')
                    return HTTPFound(location=came_from, headers=headers)
    
            self.request.session.flash(u'Failed to login.')
            return HTTPFound(location=came_from)
        return dict(
            form=FormRenderer(form),
            username=self.username
        )

    @view_config(route_name='logout')
    def logout(self):
        self.request.session.invalidate()
        self.request.session.flash(u'Logged out successfully.')
        headers = forget(self.request)
        return HTTPFound(location=self.request.route_url('home'), headers=headers)
