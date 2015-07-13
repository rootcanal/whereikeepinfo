import os
import smtplib
import time

from passlib.hash import bcrypt
from pyramid.response import Response
from pyramid.response import FileResponse
from pyramid.view import view_config
from pyramid.security import authenticated_userid
from pyramid.security import remember
from pyramid.security import forget
from pyramid.renderers import render
from pyramid.httpexceptions import HTTPFound
from pyramid_simpleform.renderers import FormRenderer
from pyramid_simpleform import Form
from itsdangerous import URLSafeTimedSerializer

from .models import User
from .forms import RegistrationSchema
from .forms import LoginSchema


def _get_username(request, session):
    userid = authenticated_userid(request)
    print 'userid:', userid
    if userid is not None:
        return session.query(User).filter(User.username==userid).first()


def resume(request):
    response = FileResponse(
        request.registry.current_resume,
        request=request,
        content_type='application/pdf'
    )
    return response


def home(request, session):
    return dict(
        username=_get_username(request, session)
    )

def register(request, session):
    form = Form(request, schema=RegistrationSchema)

    if 'form.submitted' in request.POST and form.validate():
        username = form.data['username']
        user = User(
            username=username,
            password=form.data['password'],
            name=form.data['name'],
            email=form.data['email'],
            created_at=time.time()
        )
        session.add(user)

        serializer = URLSafeTimedSerializer(request.registry.verification_key)
        token = serializer.dumps(form.data['email'], salt=request.registry.verification_salt)
        token_url = request.route_url('verify', token=token)

        server = smtplib.SMTP(request.registry.email_server, request.registry.email_port)
        server.ehlo()
        server.starttls()
        server.login(request.registry.email_user, request.registry.email_password)
        body = '\r\n'.join(['To: %s' % (form.data['email'], ),
                            'From: %s' % (request.registry.email_user, ),
                            'Subject: %s' % ('Thanks for registering at whereikeep.info', ),
                            '',
                            'Click here to complete registration %s' % (token_url, )
                           ])
        server.sendmail(request.registry.email_user, [form.data['email']], body)

        headers = remember(request, username)

        redirect_url = request.route_url('home')

        request.session.flash(u'Registration email sent. '\
                               'Follow instructions in email to complete registration')

        return HTTPFound(location=redirect_url, headers=headers)

    return dict(
        form=FormRenderer(form),
        username=_get_username(request, session)
    )


def verify(request, session, token=None):

    serializer = URLSafeTimedSerializer(request.registry.verification_key)
    try:
        email = serializer.loads(
            token,
            salt=request.registry.verification_salt,
            max_age=3600
        )
    except:
        request.session.flash(u'Unable to verify your account. sry...')
    request.session.flash(u'Account verified!')

    user = session.query(User).filter(email==email).first()
    user.verified = True
    user.verified_at = time.time()
    session.update(user)

    headers = remember(request, user.username)

    return dict(username=user.username, user=user)


def user(request, session, username=None):
    user = session.query(User).filter(username==username).first()
    return dict(
        user=user,
        username=user.username
    )


def login(request, session):
    home_view = request.route_url('home')
    came_from = request.params.get('came_from', home_view)

    form = Form(request, schema=LoginSchema)

    if 'form.submitted' in request.POST and form.validate():
        username = form.data['username']
        password = form.data['password']

        user = session.query(User).filter(User.username==username).first()
        if user and bcrypt.verify(password, user.password):
            headers = remember(request, username)
            request.session.flash(u'Logged in successfully.')
            return HTTPFound(location=came_from, headers=headers)

        request.session.flash(u'Failed to login.')
        return HTTPFound(location=came_from)
    return dict(
        logged_in=authenticated_userid(request),
        form=FormRenderer(form),
        username=_get_username(request, session)
    )


def logout(request):
    request.session.invalidate()
    request.session.flash(u'Logged out successfully.')
    headers = forget(request)
    return HTTPFound(location=request.route_url('home'), headers=headers)
