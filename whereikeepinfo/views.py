import os

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

from .models import User
from .models import crypt
from .forms import RegistrationSchema


def resume(request):
    response = FileResponse(
        request.registry.current_resume,
        request=request,
        content_type='application/pdf'
    )
    return response


def home(request):
    return dict(
        username=authenticated_userid(request),
    )

def register(request, session):
    form = Form(request, schema=RegistrationSchema)

    if 'form.submitted' in request.POST and form.validate():
        username = form.data['username']
        user = User(
            username=username,
            password=form.data['password'],
            name=form.data['name'],
            email=form.data['email']
        )
        session.add(user)

        headers = remember(request, username)

        redirect_url = request.route_url('home')

        return HTTPFound(location=redirect_url, headers=headers)

    return dict(
        form=FormRenderer(form)
    )


def user(request, session, username=None):
    user = session.query(User).filter(username==username).first()
    return dict(
        user=user
    )


def login(request, session):
    home_view = request.route_url('home')
    came_from = request.params.get('came_from', home_view)

    post_data = request.POST
    if 'submit' in post_data:
        login = post_data['login']
        password = post_data['password']

        user = session.query(User).filter(User.username==login).first()
        if user and crypt.check(user.password, password):
            headers = remember(request, login)
            request.session.flash(u'Logged in successfully.')
            return HTTPFound(location=came_from, headers=headers)

        request.session.flash(u'Failed to login.')
        return HTTPFound(location=came_from)
    return dict(logged_in=authenticated_userid(request))


def logout(request):
    request.session.invalidate()
    request.session.flash(u'Logged out successfully.')
    headers = forget(request)
    return HTTPFound(location=request.route_url('home'), headers=headers)
