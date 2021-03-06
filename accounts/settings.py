### FROM MP-ACCOUNTS SETTINGS ###
# registration
REGISTRATION_FORM_FIELDS = {
    'first_and_last': True,
    'preferred_name': True,
    'username': True,
    'email': True,
    'password': True,
    'confirm_password': True,
    'captcha': True,
}

LOG_IN_WITH_EMAIL = True

ADMIN_URL = None
CMS_ADMIN_BUTTON = True
CMS_URL = 'admin'

# authentication

SOCIAL_AUTH_LOGIN_OPTIONS = [
    'Twitter',
    'Facebook',
    # 'Google',
]

SOCIAL_AUTH_NEW_USER_URL = '/account/?new=true&login=django'
SOCIAL_AUTH_FACBEOOK_NEW_USER_URL = '/account/?new=true&login=facebook'
SOCIAL_AUTH_GOOGLE_PLUS_NEW_USER_URL = '/account/?new=true&login=gplus'
SOCIAL_AUTH_TWITTER_NEW_USER_URL = '/account/?new=true&login=twitter'

SOCIAL_AUTH_LOGIN_REDIRECT_URL = '/account/?login=django'
SOCIAL_AUTH_GOOGLE_PLUS_LOGIN_REDIRECT_URL = '/account/?login=gplus'
SOCIAL_AUTH_FACEBOOK_LOGIN_REDIRECT_URL = '/account/?login=facebook'
SOCIAL_AUTH_TWITTER_LOGIN_REDIRECT_URL = '/account/?login=twitter'

# SOCIAL_AUTH_GOOGLE_PLUS_KEY = ''
# SOCIAL_AUTH_GOOGLE_PLUS_SECRET = ''
# SOCIAL_AUTH_GOOGLE_PLUS_SCOPES = (
#     'https://www.googleapis.com/auth/plus.login', # Minimum needed to login
#     'https://www.googleapis.com/auth/plus.profile.emails.read', # emails
# )

SOCIAL_AUTH_FACEBOOK_KEY = ''
SOCIAL_AUTH_FACEBOOK_SECRET = ''
SOCIAL_AUTH_FACEBOOK_SCOPE = ['public_profile,email']

SOCIAL_AUTH_TWITTER_KEY = ''
SOCIAL_AUTH_TWITTER_SECRET = ''

# SOCIAL_AUTH_EMAIL_FORCE_EMAIL_VALIDATION = True
SOCIAL_AUTH_EMAIL_VALIDATION_FUNCTION = 'accounts.pipeline.send_validation_email'
SOCIAL_AUTH_EMAIL_VALIDATION_URL = '/account/validate'

SOCIAL_AUTH_DISCONNECT_REDIRECT_URL = '/'

# Our authentication pipeline
SOCIAL_AUTH_PIPELINE = (
    'accounts.pipeline.clean_session',

    # Get the information we can about the user and return it in a simple
    # format to create the user instance later. On some cases the details are
    # already part of the auth response from the provider, but sometimes this
    # could hit a provider API.
    'social.pipeline.social_auth.social_details',

    # Get the social uid from whichever service we're authing thru. The uid is
    # the unique identifier of the given user in the provider.
    'social.pipeline.social_auth.social_uid',

    # Verifies that the current auth process is valid within the current
    # project, this is were emails and domains whitelists are applied (if
    # defined).
    'social.pipeline.social_auth.auth_allowed',

    # Checks if the current social-account is already associated in the site.
    'social.pipeline.social_auth.social_user',

    # Make up a username for this person, appends a random string at the end if
    # there's any collision.
    'social.pipeline.user.get_username',

    # Confirm with the user that they really want to make an account, also
    # make them enter an email address if they somehow didn't
    'accounts.pipeline.confirm_account',

    # Send a validation email to the user to verify its email address.
    'social.pipeline.mail.mail_validation',

    # Create a user account if we haven't found one yet.
    'social.pipeline.user.create_user',

    # Create the record that associated the social account with this user.
    'social.pipeline.social_auth.associate_user',

    # Populate the extra_data field in the social record with the values
    # specified by settings (and the default ones like access_token, etc).
    'social.pipeline.social_auth.load_extra_data',

    # Update the user record with any changed info from the auth service.
    'social.pipeline.user.user_details',

    # Set up default django permission groups for new users.
    'accounts.pipeline.set_user_permissions',

    # Grab relevant information from the social provider (avatar)
    'accounts.pipeline.get_social_details',

    # 'social.pipeline.debug.debug',
    'accounts.pipeline.clean_session',
)

EMAIL_HOST_USER = 'noreply@ecotrust.org'
DEFAULT_FROM_EMAIL = 'noreply@ecotrust.org'
SERVER_EMAIL = 'noreply@ecotrust.org'
PROJECT_SITE = 'https://portal.midatlanticocean.org'
PROJECT_NAME = 'Mid-Atlantic Portal'

FORGOT_EMAIL_SUBJECT = 'Password Reset Request'

NOCAPTCHA = True
RECAPTCHA_PUBLIC_KEY = 'Manage Recaptcha via Google Account to get public key'
RECAPTCHA_PRIVATE_KEY = 'SetInLocalSettings'

ACCOUNTS_TEMPLATES = {
    'index': 'accounts/index.html',
    'login': 'accounts/login.html',
    'user_detail_form': 'accounts/user_detail_form.html',
    'change_password_form': 'accounts/change_password_form.html',
    'registration_error': 'accounts/registration_error.html',
    'success': 'accounts/success.html',
    'register': 'accounts/register.html',
    'check_your_email': 'accounts/check_your_email.html',
    'social_confirm': 'accounts/social_confirm.html',
    'verify_email_txt': 'accounts/mail/verify_email.txt',
    'verify_email_html': 'accounts/mail/verify_email.html',
    'verify_email_success': 'accounts/verify_email_success.html',
    'debug': 'accounts/debug.html',
    'wait_for_email': 'accounts/forgot/wait_for_email.html',
    'forgot': 'accounts/forgot/forgot.html',
    'reset_successful': 'accounts/forgot/reset_successful.html',
    'reset': 'accounts/forgot/reset.html',
}
### END MP-ACCOUNTS SETTINGS ###
