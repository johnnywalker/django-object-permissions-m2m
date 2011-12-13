from django.conf import settings
from django.db import models, IntegrityError
from django.db.models import Q
from django.contrib.auth.models import User

from object_permissions_m2m.registration import user_has_perm, get_model_perms

class ObjectPermBackend(object):
    supports_object_permissions = True
    supports_anonymous_user = True

    def __init__(self, *args, **kwargs):
        if hasattr(settings, 'ANONYMOUS_USER_ID'):
            id = settings.ANONYMOUS_USER_ID
            try:
                self.anonymous, new = User.objects.get_or_create(id=id,
                        username='anonymous')
            except IntegrityError:
                # Couldn't get the UID we were told to get, but we were still
                # told to get *an* anonymous user, so we'll make one. Note
                # that this could totally cause a second IntegrityError, which
                # we'll allow to propagate. That's fine; worse things have
                # happened, and it will hopefully LART the user sufficiently.
                self.anonymous, new = User.objects.get_or_create(
                        username='anonymous')
        else:
            self.anonymous = None

    def authenticate(self, username, password):
        """ Empty method, this backend does not authenticate users """
        return None

    def has_perm(self, user_obj, perm, obj=None):
        """
        Return whether the user has the given permission on the given object.
        """

        if not user_obj.is_authenticated():
            if self.anonymous:
                user_obj = self.anonymous
            else:
                return False

        if obj is None:
            return False

        return user_has_perm(user_obj, perm, obj, True)

    def get_all_permissions(self, user_obj, obj=None):
        """
        Get a list of all permissions for the user on the given object.

        This includes permissions given through groups.
        """

        if not user_obj.is_authenticated():
            if self.anonymous:
                user_obj = self.anonymous
            else:
                return []

        if obj is None or not isinstance(obj, models.Model):
            return []

        model = obj.__class__
        perms = get_model_perms(model)
        
        user_perms = []

        for perm in perms:
            q = Q(**{ 
                'user_perm_%s' % perm : user_obj,
            }) | Q(**{
                'group_perm_%s__user' % perm : user_obj,
            })
            if model.objects.filter(q).exists():
                user_perms.append(perm)

        return user_perms

    def get_group_permissions(self, user_obj, obj=None):
        """
        Get a list of permissions for this user's groups on the given object.
        """

        if not user_obj.is_authenticated():
            if self.anonymous:
                user_obj = self.anonymous
            else:
                return []

        if obj is None or not isinstance(obj, models.Model):
            return []

        model = obj.__class__
        perms = get_model_perms(model)
        
        group_perms = []

        for perm in perms:
            q = Q(**{
                'group_perm_%s__user_set__user' % perm : user,
            })
            if model.objects.filter(q).exists():
                group_perms.append(perm)

        return group_perms
