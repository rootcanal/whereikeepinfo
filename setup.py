from setuptools import setup, find_packages

requires = [
    'pyramid',
    'pyramid_chameleon',
    'formencode',
    'pyramid_tm',
    'SQLAlchemy',
    'passlib',
    'itsdangerous',
    'waitress',
    ]

setup(name='whereikeepinfo',
      version='0.0.1',
      description='whereikeepinfo',
      author='Philip Ramsey',
      author_email='philip@whereikeep.info',
      url='http://whereikeep.info',
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      test_suite='whereikeepinfo',
      install_requires=requires,
      entry_points="""\
      [paste.app_factory]
      main = whereikeepinfo:main
      """,
      )
