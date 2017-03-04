from django.conf.urls import url
from django.conf import settings
from django.views.generic import RedirectView
from accounts.views import UserDetailView, ChangePasswordView, index, register, forgot, forgot_reset, social_confirm, verify_new_email, verify_email, promote_user, debug_page
from django.contrib.auth.views import logout

urlpatterns = [
    url(r'^login/$', RedirectView.as_view(pattern_name='account:index'),
        name='login'),
    url(r'^logout/$', logout, {'next_page': '/'},
        name='logout'),
    url(r'^register/$', register, name='register'),
    url(r'^edit/$', UserDetailView.as_view(), name='edit'),
    url(r'^forgot/$', forgot, name='forgot_password'),
    url(r'^forgot/(?P<code>[a-f0-9]{32})$', forgot_reset,
        name='forgot_reset'),
    url(r'^confirm-account/$', social_confirm,
        name='social_confirm'),
    url(r'^verify_new_email$', verify_new_email,
        name='verify_new_email'),
    url(r'^verify/(?P<code>[a-f0-9]{32})$', verify_email,
        name='verify_email'),
    url(r'^change-password/$', ChangePasswordView.as_view(),
        name='change_password'),
    url(r'^$', index, name="index"),
]


if settings.DEBUG:
    urlpatterns.extend([
        url(r'^promote-user$', promote_user),
        url(r'^debug$', debug_page)
    ])


def urls(namespace='account'):
    """Returns a 3-tuple for use with include().

    The including module or project can refer to urls as namespace:urlname,
    internally, they are referred to as app_name:urlname.
    """
    return (urlpatterns, 'account', namespace)
