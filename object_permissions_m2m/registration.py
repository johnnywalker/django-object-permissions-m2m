from operator import or_
from warnings import warn

from django.conf import settings
from django.contrib.auth.models import User, Group
from django.core.exceptions import ObjectDoesNotExist
from django import db
from django.db import models, transaction
from django.db.models import Model, Q, Sum

from object_permissions_m2m.signals import granted, revoked


TESTING = settings.TESTING if hasattr(settings, 'TESTING') else False


"""
Registration functions.

This is the meat and gravy of the entire app.

In order to use permissions with a Model, that Model's permissions must be
registered in advance. Registration can only be done once per Model, at model
definition time, and must include all permissions for that Model.

 register(["spam", "eggs", "toast"], Breakfast)

Once registered, permissions may be set for any pairing of an instance of that
Model and an instance of a User or Group.

Technical tl;dr: Registration can only happen once because Object Permissions
dynamically creates new models to store the permissions for a specific model.
Since the dynamic models need to be database-backed, they can't be altered
once defined and they must be defined before validation. We'd like to offer
our sincerest assurance that, even though dynamic models are dangerous, our
highly trained staff has expertly wrestled these majestic, fascinating,
terrifying beasts into cages, and now they are yours to tame and own. Buy one
today!

...Okay, that got weird. But you get the point. Only register() a model once.
"""

class RegistrationException(Exception):
    pass


class UnknownPermissionException(Exception):
    pass


__all__ = (
    'register',
    'get_class',
    'grant', 'grant_group',
    'revoke', 'revoke_group',
    'get_user_perms', 'get_group_perms',
    'revoke_all', 'revoke_all_group',
    'set_user_perms', 'set_group_perms',
    'get_users', 'get_users_all', 'get_users_any',
    'get_groups', 'get_groups_all', 'get_groups_any',
    "user_has_any_perms", "group_has_any_perms",
    "user_has_all_perms", "group_has_all_perms",
    'get_model_perms',
    'filter_on_perms',
)

registered = []
"""
A list of registered Models.
"""

permissions_for_model = {}
"""
A mapping of Models to lists of permissions defined for that model.
"""

class_names = {}
"""
A mapping of Class name to Class object
"""

params_for_model = {}
"""
A mapping of Models to their param dictionaries.
"""

forbidden = set([
    "full_clean",
    "clean_fields",
    "clean",
    "validate_unique",
    "save",
    "pk",
    "delete",
    "get_absolute_url",
])
"""
Names reserved by Django for Model instances.
"""

_DELAYED = []
def register(params, model, app_label=None):
    """
    Register permissions for a Model.

    The permissions should be a list of names of permissions, e.g. ["eat",
    "order", "pay"]. This function will insert a row into the permission table
    if one does not already exist.

    For backwards compatibility, this function can also take a single
    permission instead of a list. This feature should be considered
    deprecated; please fix your code if you depend on this.
    """

    if isinstance(params, (str, unicode)):
        warn("Using a single permission is deprecated!")
        perms = [params]
    
    if app_label is None:
        warn("Registration without app_label is deprecated!")
        warn("Adding %s permissions table to object_permission app.  Note that you may not be able to migrate with south" % model)
        app_label = "object_permissions_m2m"

    # REPACK - for backward compatibility repack list of perms as a dict
    if isinstance(params, (list, tuple)):
        perms = params
        params = {'perms':params}
    else:
        perms = params['perms']

    for perm in perms:
        if perm in forbidden:
            raise RegistrationException("Permission %s is a reserved name!")

    # REPACK - For backwards compatibility and flexibility with parameters,
    # repack permissions list to ensure it is a dict of dicts
    if isinstance(perms, (list, tuple)):
        # repack perm list as a dictionary
        repack = {}
        for perm in perms:
            repack[perm] = {}
        params['perms'] = repack

    try:
        _register(params, model, app_label)
    except db.utils.DatabaseError:
        # there was an error, likely due to a missing table.  Delay this
        # registration.
        _DELAYED.append((params, model, app_label))


@transaction.commit_manually
def _register(params, model, app_label):
    """
    Real method for registering permissions.

    This method is private; please don't call it from outside code.
    This inner function is required because its logic must also be available
    to call back from _register_delayed for delayed registrations.
    """
    try:
        if model in registered:
            warn("Tried to double-register %s for permissions!" % model)
            return

        _model_name = model.__name__.lower()

        for perm in params['perms']:
            # create a ManyToManyField for each permission
            # field names follow this pattern: "user/group_perm_[perm name]"
            _perm = perm.lower()
            field_names = (
                'user_perm_%s' % _perm, 
                'group_perm_%s' % _perm,
                )

            existing_field_names = model._meta.get_all_field_names()
            if field_names[0] in existing_field_names:
                raise RegistrationException('Cannot contribute ManyToManyField '
                    'named %s to %s for permission "%s" - field already exists' \
                    % (field_names[0], model.__name__, perm))
            if field_names[1] in existing_field_names:
                raise RegistrationException('Cannot contribute ManyToManyField '
                    'named %s to %s for permission "%s" - field already exists' \
                    % (field_names[1], model.__name__, perm))


            field = models.ManyToManyField(User,
                null=True,
                blank=True,
                verbose_name=('User "%s" permission' % perm),
                help_text=params['perms'][perm].get('description', ''),
                related_name=('perm_%s_%s_set' % (_perm, _model_name)),
                )
            field.contribute_to_class(model, field_names[0])
            field = models.ManyToManyField(Group, 
                null=True,
                blank=True,
                verbose_name=('Group "%s" permission' % perm),
                help_text=params['perms'][perm].get('description', ''),
                related_name=('perm_%s_%s_set' % (_perm, _model_name)),
                )
            field.contribute_to_class(model, field_names[1])

        registered.append(model)
        permissions_for_model[model] = params['perms']
        params_for_model[model] = params
        class_names[model.__name__] = model
    except:
        transaction.rollback()
        raise
    finally:
        transaction.commit()


def _register_delayed(**kwargs):
    """
    Register all permissions that were delayed waiting for database tables to
    be created.

    Don't call this from outside code.
    """
    try:
        for args in _DELAYED:
            _register(*args)
        models.signals.post_syncdb.disconnect(_register_delayed)
    except db.utils.DatabaseError:
        # still waiting for models in other apps to be created
        pass


models.signals.post_syncdb.connect(_register_delayed)


if TESTING:
    # XXX Create test tables only when TEST mode.  These models will be used in
    # various unittests.  This is used so that we do add unneeded models in a
    # production deployment.
    from django.db import models
    class TestModel(models.Model):
        name = models.CharField(max_length=32)
    class TestModelChild(models.Model):
        parent = models.ForeignKey(TestModel, null=True)
    class TestModelChildChild(models.Model):
        parent = models.ForeignKey(TestModelChild, null=True)
        
    TEST_MODEL_PARAMS = {
        'perms' : {
            # perm with both params
            'Perm1': {
                'description':'The first permission',
                'label':'Perm One'
            },
            # perm with only description
            'Perm2': {
                'description':'The second permission',
            },
            # perm with only label
            'Perm3': {
                'label':'Perm Three'
            },
            # perm with no params
            'Perm4': {}
        },
        'url':'test_model-detail',
        'url-params':['name']
    }
    register(TEST_MODEL_PARAMS, TestModel, 'object_permissions_m2m')
    register(['Perm1', 'Perm2','Perm3','Perm4'], TestModelChild, 'object_permissions_m2m')
    register(['Perm1', 'Perm2','Perm3','Perm4'], TestModelChildChild, 'object_permissions_m2m')


def get_class(class_name):
    return class_names[class_name]


def grant(user, perm, obj):
    """
    Grant a permission to a User.
    """

    _perm = perm.lower()

    field_name = 'user_perm_%s' % _perm
    
    try:
        manager = getattr(obj, field_name)
    except AttributeError:
        raise UnknownPermissionException(perm)

    if manager.filter(pk=user.pk).count() == 0:
        manager.add(user)

        granted.send(sender=user, perm=perm, object=obj)


def grant_group(group, perm, obj):
    """
    Grant a permission to a Group.
    """

    _perm = perm.lower()

    field_name = 'group_perm_%s' % _perm
    
    try:
        manager = getattr(obj, field_name)
    except AttributeError:
        raise UnknownPermissionException(perm)

    if manager.filter(pk=group.pk).count() == 0:
        manager.add(group)

        granted.send(sender=group, perm=perm, object=obj)
    
def set_user_perms(user, perms, obj):
    """
    Set User permissions to exactly the specified permissions.
    """    

    if perms:
        model = obj.__class__
        
        all_perms = dict((p, False) for p in get_model_perms(model))
        for perm in perms:
            all_perms[perm] = True

        for perm in all_perms:
            _perm = perm.lower()

            manager = getattr(obj, 'user_perm_%s' % _perm)
            filtered = manager.filter(pk=user.pk)
            if not all_perms[perm] and filtered.count() > 0:
                manager.remove(user)
                revoked.send(sender=user, perm=perm, object=obj)
            elif all_perms[perm] and filtered.count() == 0:
                manager.add(user)
                granted.send(sender=user, perm=perm, object=obj)
            
    else:
        # removing all perms.
        revoke_all(user, obj)

    return perms


def set_group_perms(group, perms, obj):
    """
    Set group permissions to exactly the specified permissions.
    """
    if perms:
        model = obj.__class__
        
        all_perms = dict((p, False) for p in get_model_perms(model))
        for perm in perms:
            all_perms[perm] = True
    
        for perm in all_perms:
            _perm = perm.lower()

            manager = getattr(obj, 'group_perm_%s' % _perm)

            filtered = manager.filter(pk=group.pk)
            if not all_perms[perm] and filtered.count() > 0:
                manager.remove(group)
                revoked.send(sender=group, perm=perm, object=obj)
            elif all_perms[perm] and filtered.count() == 0:
                manager.add(group)
                granted.send(sender=group, perm=perm, object=obj)
            
    else:
        # removing all perms.
        revoke_all_group(group, obj)

    return perms


def revoke(user, perm, obj):
    """
    Revoke a permission from a User.
    """

    _perm = perm.lower()

    try:
        manager = getattr(obj, 'user_perm_%s' % _perm)
    except AttributeError:
        # means this perm doesn't exist, fail silently
        return
    if manager.filter(pk=user.pk).count() > 0:
        manager.remove(user)
        revoked.send(sender=user, perm=perm, object=obj)
    

def revoke_group(group, perm, obj):
    """
    Revokes a permission from a Group.
    """

    _perm = perm.lower()

    try:
        manager = getattr(obj, 'group_perm_%s' % _perm)
    except AttributeError:
        # means this perm doesn't exist, fail silently
        return
    if manager.filter(pk=group.pk).count() > 0:
        manager.remove(group)
        revoked.send(sender=group, perm=perm, object=obj)
    

def revoke_all(user, obj):
    """
    Revoke all permissions from a User.
    """

    model = obj.__class__
    perms = get_model_perms(model)

    for perm in perms:
        _perm = perm.lower()

        manager = getattr(obj, 'user_perm_%s' % _perm)
        if manager.filter(pk=user.pk).count() > 0:
            manager.remove(user)
            revoked.send(sender=user, perm=perm, object=obj)

def revoke_all_group(group, obj):
    """
    Revoke all permissions from a Group.
    """

    model = obj.__class__
    perms = get_model_perms(model)

    for perm in perms:
        _perm = perm.lower()

        manager = getattr(obj, 'group_perm_%s' % _perm)
        if manager.filter(pk=group.pk).count() > 0:
            manager.remove(group)
            revoked.send(sender=group, perm=perm, object=obj)

def get_user_perms(user, obj, groups=True):
    """
    Return the permissions that the User has on the given object.
    """
    
    model = obj.__class__
    perms = get_model_perms(model)

    user_perms = []

    for perm in perms:
        _perm = perm.lower()
        q = Q(**{ 'user_perm_%s' % _perm : user })
        if groups:
            q |= Q(**{ 'group_perm_%s__user' % _perm : user })

        if model.objects.filter(pk=obj.pk).filter(q).count() > 0:
            user_perms.append(perm)
    
    return user_perms


def get_user_perms_any(user, klass, groups=True):
    """
    return permission types that the user has on a given Model
    """

    perms = get_model_perms(klass)

    user_perms = []
    for perm in perms:
        _perm = perm.lower()
        
        q = Q(**{ 'user_perm_%s' % _perm : user })
        if groups:
            q |= Q(**{ 'group_perm_%s__user' % _perm : user })

        if klass.objects.filter(q).count() > 0:
            user_perms.append(perm)
    
    return user_perms


def get_group_perms(group, obj, groups=True):
    """
    Return the permissions that the Group has on the given object.

    @param groups - does nothing, compatibility with user version
    """
    
    model = obj.__class__
    perms = get_model_perms(model)

    group_perms = []

    for perm in perms:
        _perm = perm.lower()

        manager = getattr(obj, 'group_perm_%s' % _perm)
        if manager.filter(pk=group.pk).count() > 0:
            group_perms.append(perm)
    
    return group_perms


def get_group_perms_any(group, klass):
    """
    return permission types that the user has on a given Model
    """

    _model_name = klass.__name__.lower()

    perms = get_model_perms(klass)

    group_perms = []
    for perm in perms:
        _perm = perm.lower()

        manager = getattr(group, 'perm_%s_%s_set' % \
            (_perm, _model_name))
        if manager.count() > 0:
            group_perms.append(perm)
        
    return group_perms


def get_model_perms(model):
    """
    Return all available permissions for a model.

    This function accepts both Models and model instances.
    """

    if isinstance(model, models.Model):
        # Instance; get the class
        model = model.__class__
    elif not issubclass(model, models.Model):
        # Not a Model subclass
        raise RegistrationException(
            "%s is neither a model nor instance of one" % model)

    if model not in registered:
        raise RegistrationException(
            "Tried to get permissions for unregistered model %s" % model)
    return permissions_for_model[model]


def user_has_perm(user, perm, obj, groups=True):
    """
    Check if a User has a permission on a given object.

    If groups is True, the permissions of all Groups containing the user
    will also be considered.

    Silently returns False in case of several errors:

     * The model is not registered for permissions
     * The permission does not exist on this model
    """
    model = obj.__class__
    try:
        perms = get_model_perms(model)
    except RegistrationException:
        return False

    if perm not in perms:
        # not a valid permission
        return False

    _model_name = model.__name__.lower()
    _perm = perm.lower()

    lookup_key = 'perm_%s_%s_set' % \
        (_perm, _model_name)

    user_lookup = {
        lookup_key : obj,
    }
    group_lookup = {
        'groups__%s' % lookup_key : obj,
    }

    q = Q(**user_lookup)
    if groups:
        q |= Q(**group_lookup)

    q &= Q(pk=user.pk)
    return User.objects.filter(q).exists()


def group_has_perm(group, perm, obj):
    """
    Check if a Group has a permission on a given object.

    Silently returns False in case of several errors:

     * The model is not registered for permissions
     * The permission does not exist on this model
    """

    model = obj.__class__
    try:
        perms = get_model_perms(model)
    except RegistrationException:
        return False

    if perm not in perms:
        # not a valid permission
        return False

    _perm = perm.lower()

    manager = getattr(obj, 'group_perm_%s' % _perm)
    return manager.filter(pk=group.pk).exists()


def user_has_any_perms(user, obj, perms=None, groups=True):
    """
    Check whether the User has *any* permission on the given object.
    """

    instance = isinstance(obj, (Model,))
    model = obj.__class__ if instance else obj

    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)

    _model_name = model.__name__.lower()

    q = Q()
    for perm in perms:
        _perm = perm.lower()
        if instance:
            lookup_key = 'perm_%s_%s_set' % \
                (
                    _perm,
                    _model_name,
                )
            q |= Q(**{ lookup_key : obj })
            if groups:
                q |= Q(**{ 'groups__%s' % lookup_key : obj })
        else:
            lookup_key = 'perm_%s_%s_set__isnull' % \
                (
                    _perm,
                    _model_name,
                )
            q |= Q(**{ lookup_key : False })
            if groups:
                q |= Q(**{ 'groups__%s' % lookup_key : False })

    q &= Q(pk=user.pk)
    return User.objects.filter(q).exists()


def group_has_any_perms(group, obj, perms=None):
    """
    Check whether the Group has *any* permission on the given object.
    """

    instance = isinstance(obj, (Model,))
    model = obj.__class__ if instance else obj

    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)

    _model_name = model.__name__.lower()
    q = Q()
    for perm in perms:
        _perm = perm.lower()

        if instance:
            lookup_key = 'perm_%s_%s_set' % \
                (
                    _perm,
                    _model_name,
                )
            q |= Q(**{ lookup_key : obj })
        else:
            lookup_key = 'perm_%s_%s_set__isnull' % \
                (
                    _perm,
                    _model_name,
                )
            q |= Q(**{ lookup_key : False })

    q &= Q(pk=group.pk)
    return Group.objects.filter(q).exists()


def user_has_all_perms(user, obj, perms, groups=True):
    """
    Check whether the User has *all* permission on the given object.
    """

    instance = isinstance(obj, (Model,))
    model = obj.__class__ if instance else obj

    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)

    # have to make sure at least 1 instance of model exists
    # such that all of the perms specified are assigned
    # to this user
    q = Q()
    if instance:
        # limit query results to the instance passed in
        q &= Q(pk=obj.pk)

    for perm in perms:
        _perm = perm.lower()
        lookup_keys = (
            'user_perm_%s' % ( _perm, ),
            'group_perm_%s__user' % ( _perm, ),
            )
        _q = Q(**{ lookup_keys[0] : user })
        if groups:
            _q |= Q(**{ lookup_keys[1] : user })
        q &= _q

    return model.objects.filter(q).exists()


def group_has_all_perms(group, obj, perms):
    """
    Check whether the Group has *all* permission on the given object.
    
    @param group - group for which to check permissions
    @param obj - Model or Instance for which to check permissions on.
    @param perms - list of permissions that must be matched
    
    @return True if group has all permissions on an instance.  If a model class
    is given this returns True if the group has permissions on any instance of
    the model.
    """

    instance = isinstance(obj, (Model,))
    model = obj.__class__ if instance else obj

    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)

    # have to make sure at least 1 instance of model exists
    # such that all of the perms specified are assigned
    # to this user
    q = Q()
    if instance:
        # limit query results to the instance passed in
        q &= Q(pk=obj.pk)

    for perm in perms:
        _perm = perm.lower()
        lookup_key = 'group_perm_%s' % ( _perm, )
        q &= Q(**{ lookup_key : group })

    return model.objects.filter(q).exists()

    
def get_users_any(obj, perms=None, groups=True):
    """
    Retrieve the list of Users that have any of the permissions on the given
    object.

    @param perms - perms to check, or None if match *any* perms
    @param groups - include users with permissions via groups
    """
    model = obj.__class__
    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)

    _model_name = model.__name__.lower()
    q = Q()
    for perm in perms:
        _perm = perm.lower()
        lookup_key = 'perm_%s_%s_set' % \
            (
                _perm,
                _model_name,
            )
        q |= Q(**{ lookup_key : obj })
        if groups:
            q |= Q(**{ 'groups__%s' % lookup_key : obj })

    return User.objects.filter(q).distinct()


def get_users_all(obj, perms, groups=True):
    """
    Retrieve the list of Users that have all of the permissions on the given
    object.

    @param perms - perms to check
    @param groups - include users with permissions via groups
    """

    instance = isinstance(obj, (Model,))
    model = obj.__class__ if instance else obj

    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)


    # have to make sure at least 1 instance of model exists
    # such that all of the perms specified are assigned
    # to this user
    #q = Q()
    #if instance:
    #    # limit query results to the instance passed in
    #    q &= Q(pk=obj.pk)

    _model_name = model.__name__.lower()

    # cache perm lookup keys
    perm_keys = []

    q = Q()
    for perm in perms:
        _perm = perm.lower()
        lookup_keys = (
            'perm_%s_%s_set' % ( _perm, _model_name ),
            'groups__perm_%s_%s_set' % ( _perm, _model_name ),
            )
        # cache lookup key
        perm_keys.append(lookup_keys[0])

        if instance:
            _q = Q(**{ lookup_keys[0] : obj })
            if groups:
                _q |= Q(**{ lookup_keys[1] : obj })
        else:
            _q = Q(**{ '%s__isnull' % lookup_keys[0] : False })
            if groups:
                _q |= Q(**{ '%s__isnull' % lookup_keys[1] : False })

        q &= _q
    
    users = User.objects.filter(q)
    if instance:
        return users
    else:
        # since we are checking for users that have all perms on at
        # least 1 instance of 'model', we need to filter out the users
        # that have a matching model instance in every perm set

        users_with_matches = []
        for u in users.select_related():
            instances = []
            for k in perm_keys:
                _inst = set(getattr(u, k).values_list('pk', flat=True))
                if groups:
                    for g in u.groups:
                        _inst |= set(
                            getattr(g, k).values_list('pk', flat=True)
                            )
                instances.append(_inst)
            if len(instances) > 0:
                inter = instances[0]
                for i in instances[1:]:
                    inter &= i
                if len(inter) > 0:
                    # we have a good user!
                    users_with_matches.append(u)
        return users_with_matches


def get_users(obj, groups=True):
    """
    Retrieve the list of Users that have permissions on the given object.
    """
    
    return get_users_any(obj, groups=groups)


def get_groups_any(obj, perms=None):
    """
    Retrieve the list of Groups that have any of the permissions on the given
    object.

    @param perms - perms to check, or None to check for *any* perms
    """

    instance = isinstance(obj, (Model,))
    model = obj.__class__ if instance else obj

    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)

    _model_name = model.__name__.lower()
    q = Q()
    for perm in perms:
        _perm = perm.lower()

        if instance:
            lookup_key = 'perm_%s_%s_set' % \
                (
                    _perm,
                    _model_name,
                )
            q |= Q(**{ lookup_key : obj })
        else:
            lookup_key = 'perm_%s_%s_set__isnull' % \
                (
                    _perm,
                    _model_name,
                )
            q |= Q(**{ lookup_key : False })

    return Group.objects.filter(q)

    
def get_groups_all(obj, perms):
    """
    Retrieve the list of Groups that have all of the permissions on the given
    object.

    @param perms - perms to check
    """

    instance = isinstance(obj, (Model,))
    model = obj.__class__ if instance else obj

    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)


    # have to make sure at least 1 instance of model exists
    # such that all of the perms specified are assigned
    # to this group

    _model_name = model.__name__.lower()

    # cache perm lookup keys
    perm_keys = []

    q = Q()
    for perm in perms:
        _perm = perm.lower()
        lookup_key = 'perm_%s_%s_set' % ( _perm, _model_name )
        # cache lookup key
        perm_keys.append(lookup_key)

        if instance:
            q &= Q(**{ lookup_key : obj })
        else:
            q &= Q(**{ '%s__isnull' % lookup_key : False })
    
    groups = Group.objects.filter(q)
    if instance:
        return groups
    else:
        # since we are checking for users that have all perms on at
        # least 1 instance of 'model', we need to filter out the users
        # that have a matching model instance in every perm set

        groups_with_matches = []
        for g in groups.select_related():
            instances = []
            for k in perm_keys:
                instances.append(
                    set(getattr(g, k).values_list('pk', flat=True))
                    )
            if len(instances) > 0:
                inter = instances[0]
                for i in instances[1:]:
                    inter &= i
                if len(inter) > 0:
                    # we have a good group!
                    groups_with_matches.append(g)
        return groups_with_matches


def get_groups(obj):
    """
    Retrieve the list of Users that have permissions on the given object.
    """

    return get_groups_any(obj)


def perms_on_any(user, model, perms, groups=True):
    """
    Determine whether the user has any of the listed permissions on any instances of
    the Model.

    This function checks whether either user permissions or group permissions
    are set, inclusively, using logical OR.

    @param user: user who must have permissions
    @param model: model on which to filter
    @param perms: list of perms to match
    @return true if has perms on any instance of model
    
    @deprecated - replaced by user_has_any_perms()
    """
    warn('user.perms_on_any() deprecated in lieu of user.has_any_perms()', stacklevel=2)
    return user_has_any_perms(user, model, perms, groups)


def filter_on_perms(user, model, perms, groups=True):
    warn('user.filter_on_perms() deprecated in lieu of user.get_objects_any_perms()', stacklevel=2)
    return user_get_objects_any_perms(user, model, perms, groups)


def user_get_objects_any_perms(user, model, perms=None, groups=True, **related):
    """
    Make a filtered QuerySet of objects for which the User has any of the
    requested permissions, optionally including permissions inherited from
    Groups.

    @param user: user who must have permissions
    @param model: model on which to filter
    @param perms: list of perms to match
    @param groups: include perms the user has from membership in Groups
    @param related: kwargs for related models.  Each kwarg name should be a
    valid query argument, you may follow as many tables as you like and perms
    are optional  E.g. foo__bar=['xoo'], foo=None
    @return a queryset of matching objects
    """
    
    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)

    q = Q()
    for perm in perms:
        _perm = perm.lower()
        q |= Q(**{ 'user_perm_%s' % _perm : user })
        if groups:
            q |= Q(**{ 'group_perm_%s__user' % _perm : user })
    
    # related fields are built as sub-clauses for each related field.  To follow
    # the relation we must add a clause that follows the relationship path to
    # the operms table for that model, and optionally include perms.
    if related:
        
        for field in related:
            perms = related[field]
            if not perms:
                raise NotImplementedError('Perms must be specified for related fields')

            for perm in perms:
                _perm = perm.lower()
                q |= Q(**{ '%s__user_perm_%s' % (field, _perm) : user })
                if groups:
                    q |= Q(**{ '%s__group_perm_%s__user' % \
                        (field, _perm) : user })

    return model.objects.filter(q).distinct()


def group_get_objects_any_perms(group, model, perms=None, **related):
    """
    Make a filtered QuerySet of objects for which the Group has any of the 
    requested permissions.

    @param group: group who must have permissions
    @param model: model on which to filter
    @param perms: list of perms to match
    @param groups: include perms the user has from membership in Groups
    @return a queryset of matching objects
    """
    
    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)

    q = Q()
    for perm in perms:
        _perm = perm.lower()
        q |= Q(**{ 'group_perm_%s' % _perm : group })
    
    # related fields are built as sub-clauses for each related field.  To follow
    # the relation we must add a clause that follows the relationship path to
    # the operms table for that model, and optionally include perms.
    if related:
        
        for field in related:
            perms = related[field]
            if not perms:
                raise NotImplementedError('Perms must be specified for related fields')

            for perm in perms:
                _perm = perm.lower()
                q |= Q(**{ '%s__group_perm_%s' % \
                    (field, _perm) : group })

    return model.objects.filter(q).distinct()


def user_get_objects_all_perms(user, model, perms, groups=True, **related):
    """
    Make a filtered QuerySet of objects for which the User has all requested
    permissions, optionally including permissions inherited from Groups.

    @param user: user who must have permissions
    @param model: model on which to filter
    @param perms: list of perms to match
    @param groups: include perms the user has from membership in Groups
    @return a queryset of matching objects
    """
    
    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)

    q = Q()
    for perm in perms:
        _perm = perm.lower()
        _q = Q(**{ 'user_perm_%s' % _perm : user })
        if groups:
            _q |= Q(**{ 'group_perm_%s__user' % _perm : user })
        
        q &= _q
    
    # related fields are built as sub-clauses for each related field.  To follow
    # the relation we must add a clause that follows the relationship path to
    # the operms table for that model, and optionally include perms.
    if related:
        
        for field in related:
            perms = related[field]
            if not perms:
                raise NotImplementedError('Perms must be specified for related fields')

            for perm in perms:
                _perm = perm.lower()
                _q = Q(**{ '%s__user_perm_%s' % (field, _perm) : user })
                if groups:
                    _q |= Q(**{ '%s__group_perm_%s__user' % \
                        (field, _perm) : user })
                q &= _q

    return model.objects.filter(q).distinct()


def group_get_objects_all_perms(group, model, perms, **related):
    """
    Make a filtered QuerySet of objects for which the User has all requested
    permissions, optionally including permissions inherited from Groups.

    @param group: group who must have permissions
    @param model: model on which to filter
    @param perms: list of perms to match
    @param groups: include perms the user has from membership in Groups
    @return a queryset of matching objects
    """
    
    if perms:
        perms = set(perms).intersection(
            set(get_model_perms(model))
            )
    else:
        perms = get_model_perms(model)

    q = Q()
    for perm in perms:
        _perm = perm.lower()
        q &= Q(**{ 'group_perm_%s' % _perm : group })
    
    # related fields are built as sub-clauses for each related field.  To follow
    # the relation we must add a clause that follows the relationship path to
    # the operms table for that model, and optionally include perms.
    if related:
        
        for field in related:
            perms = related[field]
            if not perms:
                raise NotImplementedError('Perms must be specified for related fields')

            for perm in perms:
                _perm = perm.lower()
                q &= Q(**{ '%s__group_perm_%s' % (field, _perm) : group })

    return model.objects.filter(q).distinct()


def user_get_all_objects_any_perms(user, groups=True):
    """
    Get all objects from all registered models that the user has any permission
    for.
    
    This method does not accept a list of permissions since in most cases
    permissions will not exist across all models.  If a permission didn't exist
    on any model then it would cause an error to be thrown.
    
    @param user - user to check perms for
    @param groups - include permissions through groups
    @return a dictionary mapping class to a queryset of objects
    """
    perms = {}
    for cls in registered:
        perms[cls] = user_get_objects_any_perms(user, cls, groups=groups)
    return perms


def group_get_all_objects_any_perms(group):
    """
    Get all objects from all registered models that the group has any permission
    for.
    
    This method does not accept a list of permissions since in most cases
    permissions will not exist across all models.  If a permission didn't exist
    on any model then it would cause an error to be thrown.
    
    @param group - group to check perms for
    @return a dictionary mapping class to a queryset of objects
    """
    perms = {}
    for cls in registered:
        perms[cls] = group_get_objects_any_perms(group, cls)
    return perms


def filter_on_group_perms(group, model, perms):
    """
    Make a filtered QuerySet of objects for which the Group has any
    permissions.

    @param usergroup: Group who must have permissions
    @param model: model on which to filter
    @param perms: list of perms to match
    @param clauses: additional clauses to be added to the queryset
    @return a queryset of matching objects
    """
    warn('group.filter_on_perms() deprecated in lieu of group.get_objects_any_perms()', stacklevel=2)
    return group_get_objects_any_perms(group, model, perms)


# make some methods available as bound methods
setattr(User, 'grant', grant)
setattr(User, 'revoke', revoke)
setattr(User, 'revoke_all', revoke_all)
setattr(User, 'has_object_perm', user_has_perm)
setattr(User, 'has_any_perms', user_has_any_perms)
setattr(User, 'has_all_perms', user_has_all_perms)
setattr(User, 'get_perms', get_user_perms)
setattr(User, 'get_perms_any', get_user_perms_any)
setattr(User, 'set_perms', set_user_perms)
setattr(User, 'get_objects_any_perms', user_get_objects_any_perms)
setattr(User, 'get_objects_all_perms', user_get_objects_all_perms)
setattr(User, 'get_all_objects_any_perms', user_get_all_objects_any_perms)

# deprecated
setattr(User, 'filter_on_perms', filter_on_perms)
setattr(User, 'perms_on_any', perms_on_any)

setattr(Group, 'grant', grant_group)
setattr(Group, 'revoke', revoke_group)
setattr(Group, 'revoke_all', revoke_all_group)
setattr(Group, 'has_perm', group_has_perm)
setattr(Group, 'has_any_perms', group_has_any_perms)
setattr(Group, 'has_all_perms', group_has_all_perms)
setattr(Group, 'get_perms', get_group_perms)
setattr(Group, 'get_perms_any', get_group_perms_any)
setattr(Group, 'set_perms', set_group_perms)
setattr(Group, 'get_objects_any_perms', group_get_objects_any_perms)
setattr(Group, 'get_objects_all_perms', group_get_objects_all_perms)
setattr(Group, 'get_all_objects_any_perms', group_get_all_objects_any_perms)

# deprecated
setattr(Group, 'filter_on_perms', filter_on_group_perms)
