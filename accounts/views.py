from datetime import timedelta
from django.views.generic import FormView
from django.shortcuts import render, get_object_or_404, redirect
from django.conf import settings
from django.contrib.sessions.models import Session
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.http.response import Http404, HttpResponseRedirect, JsonResponse
from django.contrib.auth import authenticate, login
try:
    from django.urls import reverse, reverse_lazy
except (ModuleNotFoundError, ImportError) as e:
    from django.core.urlresolvers import reverse, reverse_lazy
from django.template.loader import get_template
from django.contrib.auth.decorators import login_required, user_passes_test
try:
    from urllib import quote
except Exception as e:
    from urllib.parse import quote

from accounts.models import EmailVerification
from accounts.forms import SignUpForm, ForgotPasswordForm,\
    ResetPasswordForm, SocialAccountConfirmForm, LogInForm, UserDetailForm, \
    ChangePasswordForm
from accounts.actions import apply_user_permissions, send_password_reset_email,\
    send_social_auth_provider_login_email, generate_username
from nursery.view_helpers import decorate_view


def index(request, template=None):
    """Serve up the primary account view, or the login view if not logged in
    """
    if request.user.is_anonymous:
        return login_page(request)

    c = {}

    user = request.user
    if 'social_auth' in settings.INSTALLED_APPS and getattr(user, 'social_auth', None) and user.social_auth.exists():
        c['can_change_password'] = False
    else:
        c['can_change_password'] = True

    if settings.ADMIN_URL:
        c['admin_url'] = settings.ADMIN_URL
    else:
        # Leftover wagtail workaround - both it and django wanted 'admin'
        c['admin_url'] = "/django-admin"

    c['cms_admin_button'] = settings.CMS_ADMIN_BUTTON
    c['cms_url'] = settings.CMS_URL

    if not template:
        try:
            template = settings.ACCOUNTS_TEMPLATES['index']
        except Exception as e:
            print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["index"]')
            pass
    if not template:
        template = 'accounts/index.html'

    return render(request, template, c)

def login_logic(request, c={}):
    User = get_user_model()
    next_page = request.GET.get('next', '/')
    c['success'] = False

    # should social login opitons show on page
    if 'social_auth' in settings.INSTALLED_APPS and getattr(request.user, 'social_auth', None) and request.user.social_auth.exists():
        c['allow_social_login'] = True
    else:
        c['allow_social_login'] = False

    if request.method == 'POST':
        form = LogInForm(request.POST)
        if form.is_valid:
            if 'email' in request.POST.keys():
                email = request.POST['email']
            else:
                email = None
            if 'username' in request.POST.keys():
                username = request.POST['username']
            else:
                username = None
            p = request.POST['password']

            if username:
                user = authenticate(username=username, password=p)
            else:
                # We can't actually authenticate with an email address. So, we have
                # to query the User models by email address to find a username,
                # and once we have that we can use the username to log in.
                try:
                    user = User.objects.get(email__iexact=email)
                except User.DoesNotExist:
                    form = LogInForm()
                    form.cleaned_data = {}
                    form.add_error('password', "Your login information does not match our records. Try again or click 'I forgot my password' below.")
                    c['form']=form
                    return c

                user = authenticate(username=user.username, password=p)

            if user is not None:
                if user.is_active:
                    login(request, user)
                    c['success'] = True
                    c['username'] = user.username
                    c['email'] = user.email
                    return c
                else:
                    form = LogInForm()
                    form.cleaned_data = {}
                    form.add_error('email', "Your email address is incorrect")
                    form.add_error('password', "Your password is incorrect")
                    c['form']=form
                    return c
            else:
                form = LogInForm()
                form.cleaned_data = {}

                form.add_error('password', "Your login information does not match our records. Try again or click 'I forgot my password' below.")
                c['form']=form
                return c
        else:
            form = LogInForm()
            form.cleaned_data = {}

            form.add_error('email', "Please try again")
            c['form']=form
            return c

    else:
        form = LogInForm()

    # TODO: Fix the else staircase, refactor this as a FormView

    # c = dict(GPLUS_ID=settings.SOCIAL_AUTH_GOOGLE_PLUS_KEY,
    #          GPLUS_SCOPE=' '.join(settings.SOCIAL_AUTH_GOOGLE_PLUS_SCOPES),
    c['next']=quote(next_page)
    c['form']=form

    # RDH 2020-02-11: this came from MidA DJ2 merge. Dunno if we should keep it
    try:
        from marco.settings import SOCIAL_AUTH_GOOGLE_OAUTH2_KEY, SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET, SOCIAL_AUTH_FACEBOOK_KEY, SOCIAL_AUTH_FACEBOOK_SECRET, SOCIAL_AUTH_TWITTER_KEY, SOCIAL_AUTH_TWITTER_SECRET
        google_enabled = SOCIAL_AUTH_GOOGLE_OAUTH2_KEY != 'You forgot to set the google key' and SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET != 'You forgot to set the google secret'
        facebook_enabled = SOCIAL_AUTH_FACEBOOK_KEY != 'You forgot to set the facebook key' and SOCIAL_AUTH_FACEBOOK_SECRET != 'You forgot to set the facebook secret'
        twitter_enabled = SOCIAL_AUTH_TWITTER_KEY != 'You forgot to set the twitter key' and SOCIAL_AUTH_TWITTER_SECRET != 'You forgot to set the twitter secret'
    except ImportError as e:
        # from django.conf.settings import SOCIAL_AUTH_FACEBOOK_KEY, SOCIAL_AUTH_FACEBOOK_SECRET, SOCIAL_AUTH_TWITTER_KEY, SOCIAL_AUTH_TWITTER_SECRET
        google_enabled = False
        facebook_enabled = settings.SOCIAL_AUTH_FACEBOOK_KEY != 'You forgot to set the facebook key' and settings.SOCIAL_AUTH_FACEBOOK_SECRET != 'You forgot to set the facebook secret'
        twitter_enabled = settings.SOCIAL_AUTH_TWITTER_KEY != 'You forgot to set the twitter key' and settings.SOCIAL_AUTH_TWITTER_SECRET != 'You forgot to set the twitter secret'
    show_social_options = google_enabled or facebook_enabled or twitter_enabled
    # show_social_options = False

    # c = dict(next=quote(next_page), form=form, google=google_enabled, facebook=facebook_enabled, twitter=twitter_enabled, social=show_social_options)
    c['google']=google_enabled
    c['facebook']=facebook_enabled
    c['twitter']=twitter_enabled
    c['social']=show_social_options

    return c

def login_async(request):
    login_user = login_logic(request) # run default logic
    json = {
        'success': login_user['success'],
        'username': login_user['username'],
        'email': login_user['email'],
    }
    return JsonResponse(json)

def login_page(request, return_template=None, c={}):
    """The login view. Served from index()
    """
    login_user = login_logic(request, c) # run default logic
    if login_user['success']:
        next_page = request.GET.get('next', '/')
        return HttpResponseRedirect(next_page)

    if not return_template:
        try:
            return_template = settings.ACCOUNTS_TEMPLATES['login']
        except Exception as e:
            print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["login"]')
            pass
    if not return_template:
        return_template = 'accounts/login.html'

    return render(request, return_template, login_user)

@decorate_view(login_required)
class UserDetailView(FormView):
    try:
        template_name = settings.ACCOUNTS_TEMPLATES['user_detail_form']
    except Exception as e:
        print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["user_detail_form"]')
        pass
    if not template_name:
        template_name = 'accounts/user_detail_form.html'
    form_class = UserDetailForm
    success_url = reverse_lazy('account:index')

    def get_initial(self):
        """
        Returns the initial data to use for forms on this view.
        """
        return {
            'preferred_name': self.request.user.userdata.preferred_name,
            'real_name': self.request.user.userdata.real_name,
            'email': self.request.user.email,
        }


    def form_valid(self, form):
        do_verification = False

        u = self.request.user
        u.userdata.preferred_name = form.cleaned_data['preferred_name']
        u.userdata.real_name = form.cleaned_data['real_name']
        if form.cleaned_data['email'].lower() != u.email:
            u.email = form.cleaned_data['email']
            #u.userdata.email_verified = False
            #u.emailverification_set.all().delete()
            # do_verification = True

        u.save()
        u.userdata.save()

        if do_verification:
            verify_email_address(self.request, u, activate_user=False)

        return super(FormView, self).form_valid(form)

    ### RDH: 12/01/2017
    # get_form_kwargs allows us to know the request's user when cleaning the
    # form. See forms.py for more.

    def get_form_kwargs(self):
        kwargs = super(UserDetailView, self).get_form_kwargs()
        kwargs['user'] = self.request.user
        return kwargs

@decorate_view(login_required)
class ChangePasswordView(FormView):
    try:
        template_name = settings.ACCOUNTS_TEMPLATES['change_password_form']
    except Exception as e:
        print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["change_password_form"]')
        pass
    if not template_name:
        template_name = 'accounts/change_password_form.html'
    form_class = ChangePasswordForm
    success_url = reverse_lazy('account:index')

    def get_initial(self):
        return {
            'current_password': '',
            'password1': '',
            'password2': '',
        }

    def get_form_kwargs(self):
        """Stuff the current request into the form.
        """
        kwargs = super(ChangePasswordView, self).get_form_kwargs()

        # Because this is a password form, we need access to the user & request
        # to verify that everything's ok.
        kwargs['request'] = self.request
        return kwargs

    def form_valid(self, form):
        u = self.request.user
        u.set_password(form.cleaned_data['password1'])
        u.save()

        return super(FormView, self).form_valid(form)

def register_logic(request, c={}, template=None):
    if not request.user.is_anonymous:
        return HttpResponseRedirect('/')

    c['error'] = ''
    c['success'] = False

    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            if 'real_name' in form.cleaned_data.keys():
                real_name = form.cleaned_data['real_name']
            else:
                real_name = None
            if 'preferred_name' in form.cleaned_data.keys():
                preferred_name = form.cleaned_data['preferred_name']
            else:
                preferred_name = None
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            if 'username' in form.cleaned_data.keys():
                username = form.cleaned_data['username']
            else:
                username = generate_username(email)

            user, created = get_user_model().objects.get_or_create(username=username)
            if not created:
                # This may happen if the form is submitted outside the normal
                # login flow with a user that already exists
                c['request'] = request
                c['username'] = username
                c['error'] = 'Username already exists'
                if not template:
                    try:
                        template = settings.ACCOUNTS_TEMPLATES['registration_error']
                    except Exception as e:
                        print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["registration_error"]')
                        pass
                if not template:
                    template = 'accounts/registration_error.html'
                c['template'] = template
                return c

            user.is_active = True
            user.set_password(password)
            user.email = email
            user.save()

            from .models import UserData

            userdata, created = UserData.objects.get_or_create(user=user)
            user.userdata = userdata

            user.userdata.real_name = real_name
            user.userdata.preferred_name = preferred_name
            user.userdata.save()

            apply_user_permissions(user)
            # verify_email_address(request, user)
            c['request'] = request
            c['success'] = True
            c['request'] = request
            c['username'] = username
            if not template:
                try:
                    template = settings.ACCOUNTS_TEMPLATES['success']
                except Exception as e:
                    print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["success"]')
                    pass
            if not template:
                template = 'accounts/success.html'
            c['template'] = template
            return c
    else:
        form = SignUpForm()

    c['form'] = form
    c['next'] = '#form-begin'
    c['registration_form'] = form
    c['error'] = 'Email already associated with an account'
    c['social_options'] = settings.SOCIAL_AUTH_LOGIN_OPTIONS
    c['request'] = request
    if not template:
        try:
            template = settings.ACCOUNTS_TEMPLATES['register']
        except Exception as e:
            print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["register"]')
            pass
    if not template:
        template = 'accounts/register.html'
    c['template'] = template

    # should social login opitons show on page
    if 'social_auth' in settings.INSTALLED_APPS and getattr(request.user, 'social_auth', None) and request.user.social_auth.exists():
        c['allow_social_login'] = True
    else:
        c['allow_social_login'] = False

    return c

def register_async(request):
    register_user = register_logic(request) # run default logic
    json = {
        'async': 'yes',
        'success': register_user['success'],
        'error': register_user['error'],
        'username': register_user['username'],
        'request': register_user['request'],
    }
    return JsonResponse(json)

def register_login_async(request):
    register_user = register_logic(request) # run default logic
    if register_user['success']:
        c = {}
        username = request.POST['username']
        p = request.POST['password']
        user = authenticate(username=username, password=p)
        if user is not None:
            if user.is_active:
                login(request, user)
                json = {
                    'async': 'yes',
                    'success': True,
                    'error': register_user['error'],
                    'username': user.username,
                }
                return JsonResponse(json)
    else:
        json = {
            'async': 'yes',
            'success': register_user['success'],
            'error': register_user['error'],
        }
        return JsonResponse(json)

def register_page(request, c={}):
    """The register view.
    """
    register_user = register_logic(request, c) # run default logic
    template =  c['template']
    return render(request, template, register_user)

def register(request, c={}):
    if not request.user.is_anonymous:
        return HttpResponseRedirect('/')
    register_user = register_logic(request, c) # run default logic
    template =  register_user['template']
    return render(request, template, register_user)

@login_required
def verify_new_email(request, template=None):
    if request.method != 'POST':
        raise Http404()

    verify_email_address(request, request.user, False)

    if not template:
        try:
            template = settings.ACCOUNTS_TEMPLATES['check_your_email']
        except Exception as e:
            print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["check_your_email"]')
            pass
    if not template:
        template = 'accounts/check_your_email.html'

    return render(request, template)


def social_confirm(request, template=None):
    data = request.session.get('partial_pipeline')
    if not data or not 'backend' in data.keys():
        return HttpResponseRedirect('/')

    if request.method == 'POST':
        form = SocialAccountConfirmForm(request.POST)

        if form.is_valid():
            email = form.cleaned_data['email']
            preferred_name = form.cleaned_data['preferred_name']
            real_name = form.cleaned_data['real_name']

            # if email is different than the auth provider's version, then
            # mark it as unverified.
            if email.lower() != data['kwargs']['details']['email'].lower():
                data['kwargs']['email-unverified'] = True

            # This is where the session data is stored for Facebook, but
            # this seems pretty fragile. There should be a method in PSA that
            # lets me set this directly.

            data['kwargs']['details']['email'] = email
            data['kwargs']['details']['preferred_name'] = preferred_name
            data['kwargs']['details']['real_name'] = real_name
            # add if email != data[...]email, then flag as unverified
            request.session['partial_pipeline'] = data

            if hasattr(request.session, 'modified'):
                request.session.modified = True

            return redirect(reverse('social:complete', args=(data['backend'],)))
    else:
        initial = {
            # create the form with defaults from the auth provider
            'email': data['kwargs']['details'].get('email', ''),
            'real_name': data['kwargs']['details'].get('fullname', ''),
            'preferred_name': data['kwargs']['details'].get('first_name', ''),
        }
        if data.get('backend', '') == 'twitter':
            twitter_username = data['kwargs']['details'].get('username', '')
            if twitter_username:
                initial['preferred_name'] = twitter_username
        form = SocialAccountConfirmForm(initial)

    try:
        name = data['kwargs']['details']['first_name']
    except KeyError:
        name = None

    c = {
        'form': form,
        'user_first_name': name,
        'backend': data['backend'],
    }

    if not template:
        try:
            template = settings.ACCOUNTS_TEMPLATES['social_confirm']
        except Exception as e:
            print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["social_confirm"]')
            pass
    if not template:
        template = 'accounts/social_confirm.html'

    return render(request, template, c)


def verify_email_address(request, user, activate_user=True):
    """Verify a user's email address. Typically during registration or when
    an email address is changed.

    Verifications may be sent at most once per 2 hour period (long enough so
    that a frustrated user will give up if they didn't get the email). This is
    done to prevent our mail sender from being blacklisted.
    """

    e, created = EmailVerification.objects.get_or_create(user=user)
    if created:
        e.email_to_verify = user.email
        e.activate_user = activate_user
        e.save()
    else:
        # Send the verification email again, but only if it's been a while.
        if timezone.now() - e.created < timedelta(hours=2):
            return
        e.created = timezone.now() # reset the creation date

    e.save()
    send_verification_email(request, e)


def send_verification_email(request, e, text_template=None, html_template=None):
    """Send a verification link to the specified user.
    """

    url = request.build_absolute_uri(reverse('account:verify_email',
                                             args=(e.verification_code,)))

    context = {
        'name': e.user.get_short_name(),
        'url': url,
        'host': settings.EMAIL_HOST_ADDRESS
    }
    if not text_template:
        try:
            text_template = settings.ACCOUNTS_TEMPLATES['verify_email_txt']
        except Exception as e:
            print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["verify_email_txt"]')
            pass
    if not text_template:
        text_template = 'accounts/mail/verify_email.txt'
    template = get_template(text_template)
    body_txt = template.render(context, request)
    if not html_template:
        try:
            html_template = settings.ACCOUNTS_TEMPLATES['verify_email_html']
        except Exception as e:
            print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["verify_email_html"]')
            pass
    if not html_template:
        html_template = 'accounts/mail/verify_email.html'
    template = get_template(html_template)
    body_html = template.render(context, request)

    e.user.email_user('Please verify your email address', body_txt,
                      html_message=body_html, fail_silently=False)


def verify_email(request, code, template=None):
    """Check for an email verification code in the querystring
    """

    # Is the code in the database?
    e = get_object_or_404(EmailVerification, verification_code=code)

    if e.activate_user:
        e.user.is_active = True

    e.user.userdata.email_verified = True
    e.user.userdata.save()
    e.user.save()
    e.delete()
    if not template:
        try:
            template = settings.ACCOUNTS_TEMPLATES['verify_email_success']
        except Exception as e:
            print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["verify_email_success"]')
            pass
    if not template:
        template = 'accounts/verify_email_success.html'

    return render(request, template)


def all_logged_in_users():
    sessions = Session.objects.filter(expire_date__gte=timezone.now())
    users = []
    for session in sessions:
        uid = session.get_decoded().get('_auth_user_id', None)
        if uid:
            user_obj = get_user_model().objects.filter(id=uid)
            if user_obj:
                users.append({'user': user_obj[0], 'until': session.expire_date})

    return users


@user_passes_test(lambda x: x.is_superuser)
def debug_page(request, template=None):
    """Serve up the primary account view, or the login view if not logged in
    """
    if request.user.is_anonymous:
        return login_page(request)

    c = {}

    if settings.DEBUG:
        c['users'] = get_user_model().objects.all()
        c['sessions'] = all_logged_in_users()

    if not template:
        try:
            template = settings.ACCOUNTS_TEMPLATES['debug']
        except Exception as e:
            print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["debug"]')
            pass
    if not template:
        template = 'accounts/debug.html'

    return render(request, template, c)

def forgot(request, template=None):
    """Sends a password reset link to a user's validated email address. If
    the email address isn't validated, do nothing (?)
    """
    # This doesn't make sense if the user is logged in
    if not request.user.is_anonymous:
        return HttpResponseRedirect('/')

    if request.method == 'POST':
        User = get_user_model()

        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']

            try:
                user = User.objects.get(email=email)
                if getattr(user, 'social_auth', None) and user.social_auth.exists():
                    send_social_auth_provider_login_email(request, user)
                else:
                    try:
                        send_password_reset_email(request, user)
                    except User.userdata.RelatedObjectDoesNotExist as e:
                        from accounts.models import UserData
                        UserData.objects.get_or_create(user=user)
                        send_password_reset_email(request, user)

            except User.DoesNotExist:
                pass

            if not template:
                try:
                    template = settings.ACCOUNTS_TEMPLATES['wait_for_email']
                except Exception as e:
                    print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["wait_for_email"]')
                    pass
            if not template:
                template = 'accounts/forgot/wait_for_email.html'

            return render(request, template)
    else:
        form = ForgotPasswordForm()

    c = {
        'form': form,
    }

    if not template:
        try:
            template = settings.ACCOUNTS_TEMPLATES['forgot']
        except Exception as e:
            print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["forgot"]')
            pass
    if not template:
        template = 'accounts/forgot/forgot.html'

    return render(request, template, c)


def forgot_reset(request, code, template=None):
    """Allows a user who has clicked on a validation link to reset their
    password.
    """
    # This doesn't make sense if the user is logged in
    if not request.user.is_anonymous:
        return HttpResponseRedirect('/')

    e = get_object_or_404(EmailVerification, verification_code=code)

    if not e.user.is_active:
        raise Http404('Inactive user')

    if getattr(e.user, 'social_auth', None) and e.user.social_auth.all().exists():
        raise Http404('User has a social auth login')

    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            password1 = form.cleaned_data['password1']

            e.user.set_password(password1)
            e.user.save()

            e.delete()

            if not template:
                try:
                    template = settings.ACCOUNTS_TEMPLATES['reset_successful']
                except Exception as e:
                    print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["reset_successful"]')
                    pass
            if not template:
                template = 'accounts/forgot/reset_successful.html'

            return render(request, template)

    else:
        form = ResetPasswordForm()

    c = {
        'form': form,
        'code': code,
    }

    if not template:
        try:
            template = settings.ACCOUNTS_TEMPLATES['reset']
        except Exception as e:
            print('ERROR: NO SETTING FOR ACCOUNTS_TEMPLATES["reset"]')
            pass
    if not template:
        template = 'accounts/forgot/reset.html'

    return render(request, template, c)


if settings.DEBUG:
    from django.http import HttpResponse

    def promote_user(request):
        """Promote the current user to staff status
        """
        request.user.is_staff = True
        request.user.is_superuser = True
        request.user.save()
        return HttpResponse('You are now staff+superuser', content_type='text/plain', status=200)
