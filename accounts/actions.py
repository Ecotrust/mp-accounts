from django.utils.crypto import get_random_string
import re
from django.contrib.auth.models import Group
from django.conf import settings
from django.core.urlresolvers import reverse
from django.template.context import Context
from django.template.loader import get_template
from models import EmailVerification

def apply_user_permissions(user):
    """Configure any initial permissions/groups for the user.
    """

    if not user or user.is_anonymous():
        return

    g, created = Group.objects.get_or_create(name='Designers')
    user.groups.add(g)

    # Automatically promote @pointnineseven.com users to admins
    if settings.DEBUG:
        email = user.email
        email = email.split('@')
        if len(email) == 2 and email[1] == 'pointnineseven.com':
            user.is_staff = True
            user.is_superuser = True
            user.save()


def nice_provider_name(user):
    """Return a humanized name for a user's social auth provider. This should
    be in the social auth code.
    """

    backend = [o.get_backend() for o in user.social_auth.all()]
    # The user can technically have more than one backend, but the we
    # assume that there is only one. So, just pick the first one.
    try:
        backend = backend[0].name
    except IndexError:
        # Not a social-auth-enabled user
        return 'Password'

    return {
        'google-plus': "Google",
        'facebook': "Facebook",
        'twitter': "Twitter",
    }[backend]


def send_password_reset_email(request, user):
    """Send a password reset link to the specified user.
    """

    # Reuse the EmailVerification object for a reset code
    # TODO: Maybe change the name to EmailCode or something more generic
    e, _ = EmailVerification.objects.get_or_create(user=user,
                                                   email_to_verify=user.email,
                                                   activate_user=False)

    url = request.build_absolute_uri(reverse('account:forgot_reset',
                                             args=(e.verification_code,)))

    context = Context({
        'name': user.get_short_name(),
        'url': url,
        'team_email': settings.DEFAULT_FROM_EMAIL,
    })

    template = get_template('accounts/forgot/mail/password_reset.txt')
    body_txt = template.render(context)

    # TODO: Make HTML template.
    body_html = body_txt
#     template = get_template('accounts/mail/verify_email.html')
#     body_html = template.render(context)

    user.email_user('MARCO Sign-in Information', body_txt, fail_silently=False)
    #user.email_user('MARCO Sign-in Information', body_txt,
    #                html_message=body_html, fail_silently=False)


def send_social_auth_provider_login_email(request, user):
    """Send a password reset link to the specified user.
    """

    # we don't have a name for the main page, so try a /
    url = request.build_absolute_uri('/')

    context = Context({
        'name': user.get_short_name(),
        'auth_provider_name': nice_provider_name(user),
        'site_url': url,
    })

    template = get_template('accounts/forgot/mail/you_are_using_a_social_account.txt')
    body_txt = template.render(context)
    # TODO: Make HTML template.
    # TODO: Maybe store emails in Markdown, and then dynamically convert to
    # HTML. That way we don't have to store multiple messages.
    body_html = body_txt
#     template = get_template('accounts/mail/verify_email.html')
#     body_html = template.render(context)

    user.email_user('MARCO Sign-in Information', body_txt,
                    html_message=body_html, fail_silently=False)


def generate_username(email):
    """Generates a uniquish username from an email address.
    We aren't using usernames, but we haven't modified django to ignore them
    either.
    """
    # Emails are unique, but may be too long or too short.
    # Grab at most 20 chars from the email, and then append random chars.
    username = email[:20].lower()
    username = username + '_' + get_random_string(30 - 1 - len(username))

    # Replace anything that will fail the User's validation regex
    username = re.subn(r'[^\w.@+-]', '_', username)[0]

    return username
