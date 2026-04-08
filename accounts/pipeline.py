"""
Social-auth pipeline steps for the accounts app.

Requires: social-auth-core (social_core), Django 4.2+, Python 3.10+
"""
from __future__ import annotations

from urllib.parse import urlencode, urlsplit, urlunsplit

from django.conf import settings
from django.contrib.auth.models import Group
from django.core.mail import send_mail
from django.http.response import HttpResponseRedirect
from django.shortcuts import redirect
from django.urls import reverse

from social_core.exceptions import AuthException
from social_core.pipeline.partial import partial


def get_social_details(
    user, backend, response: dict, details: dict, strategy, request, *args, **kwargs
) -> None:
    """Populate UserData from the social provider response.

    Currently extracts the user's profile picture from Facebook, Google,
    and Twitter/X.  Also seeds real_name / preferred_name for new accounts.
    """
    if backend.name == 'facebook':
        facebook_image_url = 'https://graph.facebook.com/v2.2/{id}/picture'
        user_id = response.get('id')
        if user_id:
            user.userdata.profile_image = facebook_image_url.format(id=user_id)

    elif backend.name == 'google':
        # Google People API returns an image object; swap the default ?sz=50 for sz=64.
        raw_url: str | None = response.get('image', {}).get('url')
        if raw_url:
            parts = urlsplit(raw_url)
            query = urlencode({'sz': '64'})
            user.userdata.profile_image = urlunsplit(
                (parts.scheme, parts.netloc, parts.path, query, parts.fragment)
            )

    elif backend.name == 'twitter':
        url = response.get('profile_image_url_https', '')
        if url:
            user.userdata.profile_image = url

    # Seed names and email-verified flag for brand-new accounts.
    if strategy.session_get('new_account'):
        user.userdata.real_name = details.get('real_name', '')
        user.userdata.preferred_name = details.get('preferred_name', '')
        user.userdata.email_verified = not details.get('unverified-email', True)

    user.userdata.save()


def set_user_permissions(
    strategy, backend, request, details, user=None, *args, **kwargs
) -> None:
    """Apply default Django permission groups to newly-created users."""
    from actions import apply_user_permissions
    apply_user_permissions(user)


@partial
def confirm_account(
    strategy, details, user=None, is_new: bool = False, *args, **kwargs
):
    """Show the account confirmation screen to new users so they can
    verify their email address and display name before proceeding."""
    if is_new:
        strategy.session_set('new_account', True)
        if not strategy.session_get('seen-account-confirmation'):
            strategy.session_set('seen-account-confirmation', True)
            return redirect(reverse('account:social_confirm'))
    else:
        strategy.session_set('new_account', False)


def clean_session(strategy, backend, request, details, *args, **kwargs) -> None:
    """Remove transient session keys left over from an abandoned login flow.

    Called at both the start and end of the pipeline so a partial login
    never contaminates the next attempt.
    """
    strategy.session_pop('seen-account-confirmation')


def send_validation_email(strategy, backend, code, partial_token: str) -> None:
    """Send an email-validation link during the social-auth pipeline.

    Called when SOCIAL_AUTH_EMAIL_VALIDATION_FUNCTION is set to this path.
    """
    url = f"{settings.APP_URL}{reverse('account:validate')}?verification_code={code.code}"
    send_mail(
        subject='Validate your email address',
        message=f'Please validate your email by clicking: {url}',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[code.email],
        fail_silently=False,
    )
