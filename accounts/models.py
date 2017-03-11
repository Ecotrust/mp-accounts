from django.db import models
# User = get_user_model()
from django.contrib.auth.models import User
import uuid
from django.templatetags.static import static

class EmailVerification(models.Model):
    """Model to store email address verification data.
    """
    user = models.OneToOneField(User) # one verification at a time
    email_to_verify = models.EmailField()
    verification_code = models.CharField(max_length=32, editable=False)
    # Expire verifications after XX days?
    created = models.DateTimeField(auto_now_add=True)
    activate_user = models.BooleanField(default=True,
        help_text=("If true, user.is_active will be set to true when verified."))

    def __str__(self):
        return "Verification, uid=%s, email=%s, when=%s" % (self.user.pk,
                                                            self.email_to_verify,
                                                            self.created)

    def save(self, *args, **kwargs):
        self.verification_code = uuid.uuid4().hex
        return super(EmailVerification, self).save(*args, **kwargs)


class UserData(models.Model):
    """Model to store additional user-related information.
    """
    user = models.OneToOneField(User, primary_key=True)
    email_verified = models.BooleanField(default=False,
                                         help_text=("Has this user's email "
                                                    "been verified?"))
    profile_image = models.URLField(default=static('accounts/marco_user.png'),
                                    help_text=("URL to the user's profile image."))

    real_name = models.CharField(max_length=256, default='')
    preferred_name = models.CharField(max_length=30, default='')

    show_real_name_by_default = models.BooleanField(default=False)

    def __str__(self):
        return "UserData for %s" % self.real_name

    def save(self, *args, **kwargs):
        self.user.first_name = self.preferred_name
        self.user.last_name = ''
        self.user.save()
        return super(UserData, self).save(*args, **kwargs)

# Patch the User model to return the correct names elseware.
def auth_user_get_full_name(self):
    """Returns the Real Name from the UserData model.
    """
    return self.userdata.real_name
User.get_full_name = auth_user_get_full_name

def auth_user_get_short_name(self):
    """Returns the "Preferred name" from the UserData model.
    """
    return self.userdata.preferred_name
User.get_short_name = auth_user_get_short_name


class PasswordDictionary(models.Model):
    """A collection of passwords that we don't accept.
    """
    password = models.CharField(max_length=128)

    class Meta:
        verbose_name = 'Password Dictionary'
        verbose_name_plural = 'Password Dictionary'

    def natural_key(self):
        return self.password

    def __str__(self):
        return self.password
