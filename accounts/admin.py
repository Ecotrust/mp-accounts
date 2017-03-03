from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from accounts.models import PasswordDictionary
admin.site.register(PasswordDictionary)

from accounts.models import UserData
admin.site.register(UserData)

from accounts.models import EmailVerification
admin.site.register(EmailVerification)

from import_export import fields, resources
from import_export.admin import ExportMixin
class UserResource(resources.ModelResource):
    real_name = fields.Field()
    preferred_name = fields.Field()

    def dehydrate_real_name(self, user):
        # "dehydrate_xxx" is a magic method for import export. Evidently,
        # import-export adds water.
        return user.userdata.real_name

    def dehydrate_preferred_name(self, user):
        return user.userdata.preferred_name

    class Meta:
        model = User
        fields = ('real_name', 'preferred_name', 'email', 'date_joined', 'last_login', 'is_active',)

class UserAdmin(ExportMixin, UserAdmin):
    resource_class = UserResource

admin.site.unregister(User)
admin.site.register(User, UserAdmin)
