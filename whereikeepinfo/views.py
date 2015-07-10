import os

from pyramid.response import Response
from pyramid.response import FileResponse
from pyramid.view import view_config


@view_config(route_name='resume')
def resume(request):
    response = FileResponse(
        request.registry.current_resume,
        request=request,
        content_type='application/pdf'
    )
    return response


@view_config(route_name='home', renderer='templates/home.pt')
def home(request):
    photo = request.registry.profile_photo
    photo_url = os.path.join(request.static_url('whereikeepinfo:static/%s'), photo)
    return {'profile-photo': photo_url}
