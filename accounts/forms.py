from django import forms
from accounts.widgets import BSLeftIconTextInput, BSLeftIconPasswordInput,\
    BSLeftIconEmailInput
from django.contrib.auth import get_user_model, authenticate
from accounts.models import PasswordDictionary
from django.core.exceptions import ValidationError
from captcha.fields import ReCaptchaField


def l_icon(icon_class, placeholder=None, attrs=None):
    """Shortcut for a left icon text input
    """
    attrs = attrs or {}
    if placeholder:
        attrs.update(placeholder=placeholder)
    return BSLeftIconTextInput(attrs, icon_class)


def l_icon_pw(icon_class, placeholder=None, attrs=None):
    attrs = attrs or {}
    if placeholder:
        attrs.update(placeholder=placeholder)
    return BSLeftIconPasswordInput(attrs, icon_class)


def l_icon_email(icon_class, placeholder=None, attrs=None):
    attrs = attrs or {}
    if placeholder:
        attrs.update(placeholder=placeholder)
    return BSLeftIconEmailInput(attrs, icon_class)


def password_dictionary_validator(value):
    if PasswordDictionary.objects.filter(password=value).exists():
        raise ValidationError(("You have chosen an extremely common password. "
                               "Please choose another."))


class DivForm(forms.Form):
    """A form that adds an 'as_div()' method which renders each form element
    inside <div></div> tags.
    """

    def as_div(self):
        "Returns this form rendered as HTML <div>s."
        return self._html_output(
            normal_row='<div%(html_class_attr)s>%(errors)s%(label)s %(field)s%(help_text)s</div>',
            error_row='<div>%s</div>',
            row_ender='</div>',
            help_text_html=' <span class="helptext">%s</span>',
            errors_on_separate_row=False)


class SignUpForm(DivForm):
    from marineplanner import settings
    if not settings.REGISTRATION_FORM_FIELDS or ('first_and_last' in settings.REGISTRATION_FORM_FIELDS.keys() and settings.REGISTRATION_FORM_FIELDS['first_and_last']):
        real_name = forms.CharField(min_length=3, max_length=100,
                                    widget=l_icon('fa fa-info', 'first and last name'), label="First and Last Name")

    if not settings.REGISTRATION_FORM_FIELDS or ('preferred_name' in settings.REGISTRATION_FORM_FIELDS.keys() and settings.REGISTRATION_FORM_FIELDS['preferred_name']):
        preferred_name = forms.CharField(min_length=2, max_length=100,
                                         widget=l_icon('fa fa-info', 'preferred name'), label="Preferred Name")

    # hide_real_name = forms.BooleanField()

    ### Not a field in the original Marineplanner Overhaul, do not show by default (hence 'and' instead of 'or')
    if settings.REGISTRATION_FORM_FIELDS and 'username' in settings.REGISTRATION_FORM_FIELDS.keys() and settings.REGISTRATION_FORM_FIELDS['username']:
        username = forms.CharField(min_length=4, max_length=100,
                                    widget=l_icon('fa fa-info', 'username'), label="Username")

    if not settings.REGISTRATION_FORM_FIELDS or ('email' in settings.REGISTRATION_FORM_FIELDS.keys() and settings.REGISTRATION_FORM_FIELDS['email']):
        email = forms.EmailField(widget=l_icon('fa fa-envelope-o', 'email address'))

    if not settings.REGISTRATION_FORM_FIELDS or ('password' in settings.REGISTRATION_FORM_FIELDS.keys() and settings.REGISTRATION_FORM_FIELDS['password']):
        password = forms.CharField(min_length=6, max_length=100,
                                   widget=l_icon_pw('fa fa-unlock-alt', 'password'),
                                   validators=[password_dictionary_validator])

        ### Not a field in the original Marineplanner Overhaul, do not show by default (hence 'and' instead of 'or')
        if settings.REGISTRATION_FORM_FIELDS and 'confirm_password' in settings.REGISTRATION_FORM_FIELDS.keys() and settings.REGISTRATION_FORM_FIELDS['confirm_password']:
            confirm_password = forms.CharField(min_length=6, max_length=100,
                                       widget=l_icon_pw('fa fa-unlock-alt', 'confirm password'))

    if not settings.REGISTRATION_FORM_FIELDS or ('captcha' in settings.REGISTRATION_FORM_FIELDS.keys() and settings.REGISTRATION_FORM_FIELDS['captcha']):
        captcha = ReCaptchaField()

    def clean(self):
        """Raise a validation error if the username or email address provided
        are already in use.
        """

        cleaned_data = super(SignUpForm, self).clean()

        username = cleaned_data.get('username')
        email = cleaned_data.get('email')
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')


        if get_user_model().objects.filter(username=username).exists():
            msg = u"This user name is already in use, please select another."
            self.add_error("username", msg)
        if get_user_model().objects.filter(email=email).exists():
            msg = u"This email address is already in use, please select another"
            self.add_error("email", msg)
        if not password == confirm_password:
            msg = u"'Password' does not match 'Confirm password'"
            self.add_error("password", msg)

        return cleaned_data


class LogInForm(DivForm):
    from marineplanner.settings import LOG_IN_WITH_EMAIL
    if LOG_IN_WITH_EMAIL:
        email = forms.CharField(min_length=4, max_length=100,
                               widget=l_icon('fa fa-envelope-o', 'email'))
    else:
        username = forms.CharField(min_length=4, max_length=100,
                               widget=l_icon('fa fa-envelope-o', 'username'))
    password = forms.CharField(min_length=6, max_length=100,
                               widget=l_icon_pw('fa fa-unlock-alt', 'password'))


class ForgotPasswordForm(DivForm):
    email = forms.EmailField(widget=l_icon('fa fa-envelope-o', 'email address'))


class ResetPasswordForm(DivForm):
    password1 = forms.CharField(min_length=6, max_length=100,
                                widget=l_icon_pw('fa fa-unlock-alt', 'password'),
                                validators=[password_dictionary_validator],
                                label="New password")
    password2 = forms.CharField(min_length=6, max_length=100,
                                widget=l_icon_pw('fa fa-unlock-alt', 'password'),
                                label="Confirm your password")

    def clean(self):
        """Raise a validation error if the passwords do not match.
        """
        cleaned_data = super(ResetPasswordForm, self).clean()

        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')

        if password1 != password2:
            msg = u"Your passwords do not match."
            self.add_error("password2", msg)

        return cleaned_data


class ChangePasswordForm(DivForm):
    """Form to change passwords.
    Special, as it requires a logged in user, and the current request passed
    to the constructor.
    """
    current_password = forms.CharField(min_length=1, max_length=100,
                                       widget=l_icon_pw('fa fa-unlock-alt', 'Current Password'),
                                       label="Current Password")
    password1 = forms.CharField(min_length=6, max_length=100,
                                widget=l_icon_pw('fa fa-unlock-alt', 'new password'),
                                validators=[password_dictionary_validator],
                                label="New password")
    password2 = forms.CharField(min_length=6, max_length=100,
                                widget=l_icon_pw('fa fa-unlock-alt', 'new password again'),
                                label="Confirm your new password")

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request')
        super(ChangePasswordForm, self).__init__(*args, **kwargs)

    def clean(self):
        """Raise a validation error if the passwords do not match.
        """
        cleaned_data = super(ChangePasswordForm, self).clean()

        current_password = cleaned_data.get('current_password')
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')

        result = authenticate(password=current_password,
                              username=self.request.user.username)
        if not result:
            msg = u"Your current password is incorrect."
            self.add_error('current_password', msg)
            return cleaned_data

        if current_password == password1:
            msg = (u"Please choose a password that is different "
                   u"from your current password.")
            self.add_error('password1', msg)

        elif password1 != password2:
            msg = u"Your passwords do not match."
            self.add_error("password2", msg)

        return cleaned_data


class SocialAccountConfirmForm(DivForm):
    """A form that allows the user to enter some of their pertinent details
    before continuing to the site.
    """
    email = forms.EmailField(widget=l_icon('fa fa-envelope-o', 'email address'))

    real_name = forms.CharField(min_length=3, max_length=256,
                                widget=l_icon('fa fa-user', 'Real Name'))
    preferred_name = forms.CharField(min_length=3, max_length=30,
                                     widget=l_icon('fa fa-user', 'Preferred Name'))

    def clean(self):
        """Raise a validation error if the email address provided is already in
        use.
        """
        cleaned_data = super(SocialAccountConfirmForm, self).clean()
        email = cleaned_data.get('email')

        if get_user_model().objects.filter(email=email).exists():
            msg = u"This email address is already in use, please select another"
            self.add_error("email", msg)

        return cleaned_data


class UserDetailForm(SocialAccountConfirmForm):
    """A form for a user editing their info.
    Currently identical to the Social account confirmation form.
    """

    ### From MidAtlanticPortal mp-accounts ⍾
    ### RDH: 12/01/2017
    # We need to allow users to change data without changing their email
    # We also need to make sure that users still can't steal other user's
    # emails. For this we need to check both the submitted email and the
    # request user's email. __init__ gets the user so that it can be used
    # in clean below

    def __init__(self, user, *args, **kwargs):
        super(UserDetailForm, self).__init__( *args, **kwargs)
        self.user = user

    def clean(self):
        cleaned_data = super(SocialAccountConfirmForm, self).clean()
        email = cleaned_data.get('email')
        user_email = self.user.email

        if email.lower() != user_email.lower() and get_user_model().objects.filter(email=email).exists():
            msg = u"This email address is already in use, please select another"
            self.add_error("email", msg)

        return cleaned_data

    pass
