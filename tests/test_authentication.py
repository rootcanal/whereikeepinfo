import unittest
import os

from pyramid import testing
from pyramid_simpleform import Form
from sqlalchemy import engine_from_config
from sqlalchemy.orm import sessionmaker

from whereikeepinfo.models import Base
from whereikeepinfo.views import utils
from whereikeepinfo import forms


class TestAuthentication(unittest.TestCase):

    def setUp(self):
        settings = {'sqlalchemy.url': 'sqlite:///test.sqlite'}
        engine = engine_from_config(settings, 'sqlalchemy.')
        session = sessionmaker(bind=engine)
        Base.metadata.create_all(engine)
        self.dbmaker = session

    def tearDown(self):
        os.remove('test.sqlite')

    def test_authenticate_user_returns_false_when_user_doesnt_exist(self):
        post_data = dict(username='username', password='password')
        request = testing.DummyRequest(post=post_data)
        form = Form(request, schema=forms.LoginSchema)
        self.assertFalse(utils.authenticate_user(form, self.dbmaker))
