#!/usr/bin/env python

from setuptools import setup

long_desc = open('README.md').read()

setup(name='django-object-permissions-m2m',
      version="0.1.0",
      description='A method for adding object-level or row-level permissions',
      long_description=long_desc,
      author="Jonathan Walker",
      author_email="kallous@gmail.com",
      url='http://github.com/johnnywalker/django-object-permissions-m2m',
      packages=['object_permissions_m2m'],
      include_package_data=True,
      classifiers=[
          "License :: OSI Approved :: MIT License",
          'Framework :: Django',
          'Topic :: Security',
          ],
      )
