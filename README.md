Django Object Permissions (Many-To-Many Version)
========================================

This is a fork of Django Object Permissions [web site](http://code.osuosl.org/projects/object-permissions),
which is an implementation of row level permissions. The primary difference
between this fork and the original is the use of ManyToManyField contributions
to registered models. Like the original, this app provides an authentication
backend to satisfy permissions checking.

Installation
----------------------------------------

There are several ways to install Object Permissions M2M.

Object Permissions ships a standard distutils setup.py. A classic invocation
to install from setup.py might be::

    $ python setup.py install

You may need to add sudo in order to install to the system Python.

    $ sudo python setup.py install

If you are installing Object Permissions directly into a Django app, and want
to distribute Object Permissions with your app, simply copy the
object\_permissions\_m2m folder into your Django project.

Configuring Your Django Project
----------------------------------------

1. Add "object\_permissions\_m2m" to INSTALLED\_APPS
2. Add "object\_permissions\_m2m.backend.ObjectPermBackend" to AUTHENTICATION\_BACKENDS. 
3. Run ./manage.py syncdb

Using Object Permissions
----------------------------------------

First, register some permissions onto a Model in your models.py. This can only
be done once per model; see registration.py for more information.

    >>> from object\_permissions\_m2m import register
    >>> register(['permission'], Model)

Now, that permission can be granted, revoked, or checked for any instance of
that Model.

    >>> user.grant('permission', object)
    >>> user.revoke('permission', object)
    >>> user.has\_perm('permission', object)
    >>> group.grant('permission', object)
    >>> group.revoke('permission', object)

Authors
-------

Object Permissions was originally implemented by Peter Krenesky at the Oregon
State University Open Source Lab (OSUOSL). This fork was made by Jonathan
Walker from the release maintained by Corbin Simpson.
