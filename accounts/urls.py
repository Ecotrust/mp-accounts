from django.conf.urls import url
from django.conf import settings
from django.views.generic import RedirectView
from accounts.views import UserDetailView, ChangePasswordView, index, register, forgot, forgot_reset, social_confirm, verify_new_email, verify_email, promote_user, debug_page
from django.contrib.auth.views import logout

_urlpatterns = [
    url('^$', index, name='index'),
    url('^login/$', RedirectView.as_view(pattern_name='account:index'),
        name='login'),
    url('^logout/$', logout, {'next_page': '/'},
        name='logout'),
    url('^register/$', register, name='register'),
    url('^edit/$', UserDetailView.as_view(), name='edit'),
    url('^forgot/$', forgot, name='forgot_password'),
    url('^forgot/(?P<code>[a-f0-9]{32})$', forgot_reset,
        name='forgot_reset'),
    url('^confirm-account/$', social_confirm,
        name='social_confirm'),
    url('^verify_new_email$', verify_new_email,
        name='verify_new_email'),
    url('^verify/(?P<code>[a-f0-9]{32})$', verify_email,
        name='verify_email'),
    url('^change-password/$', ChangePasswordView.as_view(),
        name='change_password'),
]


if settings.DEBUG:
    _urlpatterns.extend([
        url('^promote-user$', promote_user),
        url('^debug$', debug_page)
    ])


def urls(namespace='account'):
    """Returns a 3-tuple for use with include().

    The including module or project can refer to urls as namespace:urlname,
    internally, they are referred to as app_name:urlname.
    """
    return (_urlpatterns, 'account', namespace)
