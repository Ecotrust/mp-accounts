from datetime import timedelta
from django.views.generic import FormView
from django.shortcuts import render, get_object_or_404, redirect
from django.conf import settings
from django.contrib.sessions.models import Session
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.http.response import Http404, HttpResponseRedirect
from django.contrib.auth import authenticate, login
from django.core.urlresolvers import reverse, reverse_lazy
from django.template.loader import get_template
from django.template.context import Context
from django.contrib.auth.decorators import login_required, user_passes_test
from urllib import quote

from models import EmailVerification
from forms import SignUpForm, ForgotPasswordForm,\
    ResetPasswordForm, SocialAccountConfirmForm, LogInForm, UserDetailForm, \
    ChangePasswordForm
from actions import apply_user_permissions, send_password_reset_email,\
    send_social_auth_provider_login_email, generate_username
from nursery.view_helpers import decorate_view


def index(request):
    """Serve up the primary account view, or the login view if not logged in
    """
    if request.user.is_anonymous():
        return login_page(request)
    
    c = {}

    user = request.user
    if getattr(user, 'social_auth', None) and user.social_auth.exists():
        c['can_change_password'] = False
    else:
        c['can_change_password'] = True

    return render(request, 'accounts/index.html', c)


def login_page(request):
    """The login view. Served from index()
    """
    User = get_user_model()

    next_page = request.GET.get('next', '/')
    c = {}
    
    if request.method == 'POST':
        form = LogInForm(request.POST)
        if form.is_valid:
            email = request.POST['email']
            p = request.POST['password']

            # We can't actually authenticate with an email address. So, we have
            # to query the User models by email address to find a username,
            # and once we have that we can use the username to log in.
            try:
                user = User.objects.get(email__iexact=email)
            except User.DoesNotExist:
                form = LogInForm()
                form.cleaned_data = {}

                form.add_error('email', "Your login information does not match our records. Try again or click 'I forgot my password' below.")
                c = dict(next=quote(next_page), form=form)
                return render(request, 'accounts/login.html', c)

            user = authenticate(username=user.username, password=p)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return HttpResponseRedirect(next_page)
                else:
                    form = LogInForm()
                    form.cleaned_data = {}

                    form.add_error('email', "Your email address is incorrect")
                    form.add_error('password', "Your password is incorrect")
                    c = dict(next=quote(next_page), form=form)
                    return render(request, 'accounts/login.html', c)
            else:
                form = LogInForm()
                form.cleaned_data = {}

                form.add_error('email', "Your login information does not match our records. Try again or click 'I forgot my password' below.")
                c = dict(next=quote(next_page), form=form)
                return render(request, 'accounts/login.html', c)
        else:
            form = LogInForm()
            form.cleaned_data = {}

            form.add_error('email', "Please try again")
            c = dict(next=quote(next_page), form=form)
            return render(request, 'accounts/login.html', c)
    else:
        form = LogInForm()

    # TODO: Fix the else staircase, refactor this as a FormView

    # c = dict(GPLUS_ID=settings.SOCIAL_AUTH_GOOGLE_PLUS_KEY,
    #          GPLUS_SCOPE=' '.join(settings.SOCIAL_AUTH_GOOGLE_PLUS_SCOPES),
    c = dict(next=quote(next_page), form=form)
    
    return render(request, 'accounts/login.html', c)


@decorate_view(login_required)
class UserDetailView(FormView):
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


@decorate_view(login_required)
class ChangePasswordView(FormView):
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

def register(request):
    """Show the registration page.
    """
    
    if not request.user.is_anonymous():
        return HttpResponseRedirect('/')
    
    if request.method == 'POST': 
        form = SignUpForm(request.POST)
        if form.is_valid():
            real_name = form.cleaned_data['real_name']
            preferred_name = form.cleaned_data['preferred_name']
            email = form.cleaned_data['email']
            password = form.cleaned_data['password']
            username = generate_username(email)

            user, created = get_user_model().objects.get_or_create(username=username)
            if not created: 
                # This may happen if the form is submitted outside the normal
                # login flow with a user that already exists
                return render(request, 'accounts/registration_error.html')

            user.is_active = True
            user.set_password(password)
            user.email = email
            user.save()

            user.userdata.real_name = real_name
            user.userdata.preferred_name = preferred_name
            user.userdata.save()

            apply_user_permissions(user)
            # verify_email_address(request, user)
            
            return render(request, 'accounts/success.html')
    else:
        form = SignUpForm()

    c = {
        'form': form,
    }
    return render(request, 'accounts/register.html', c)    


@login_required
def verify_new_email(request):
    if request.method != 'POST':
        raise Http404()
    
    verify_email_address(request, request.user, False)
    
    return render(request, 'accounts/check_your_email.html')


def social_confirm(request):
    data = request.session.get('partial_pipeline')
    if not data['backend']:
        raise HttpResponseRedirect('/')

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

    return render(request, 'accounts/social_confirm.html', c)


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


def send_verification_email(request, e):
    """Send a verification link to the specified user.
    """

    url = request.build_absolute_uri(reverse('account:verify_email',
                                             args=(e.verification_code,)))

    context = Context({'name': e.user.get_short_name(), 'url': url, 'host': 'http://portal.midatlanticocean.org'})
    template = get_template('accounts/mail/verify_email.txt')
    body_txt = template.render(context)
    template = get_template('accounts/mail/verify_email.html')
    body_html = template.render(context)
    e.user.email_user('Please verify your email address', body_txt,
                      html_message=body_html, fail_silently=False)


def verify_email(request, code):
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
    return render(request, 'accounts/verify_email_success.html')


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
def debug_page(request):
    """Serve up the primary account view, or the login view if not logged in
    """
    if request.user.is_anonymous():
        return login_page(request)

    c = {}

    if settings.DEBUG:
        c['users'] = get_user_model().objects.all()
        c['sessions'] = all_logged_in_users()

    return render(request, 'accounts/debug.html', c)


def forgot(request): 
    """Sends a password reset link to a user's validated email address. If 
    the email address isn't validated, do nothing (?) 
    """
    # This doesn't make sense if the user is logged in
    if not request.user.is_anonymous():
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
                    send_password_reset_email(request, user)
                    
            except User.DoesNotExist:
                pass
            
            return render(request, 'accounts/forgot/wait_for_email.html')
    else:
        form = ForgotPasswordForm()

    c = {
        'form': form,
    }
    return render(request, 'accounts/forgot/forgot.html', c)
    
    
def forgot_reset(request, code): 
    """Allows a user who has clicked on a validation link to reset their 
    password.
    """
    # This doesn't make sense if the user is logged in
    if not request.user.is_anonymous():
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
            
            return render(request, 'accounts/forgot/reset_successful.html')

    else:
        form = ResetPasswordForm()

    c = {
        'form': form,
        'code': code, 
    }
    return render(request, 'accounts/forgot/reset.html', c)


if settings.DEBUG:
    from django.http import HttpResponse

    def promote_user(request):
        """Promote the current user to staff status
        """
        request.user.is_staff = True
        request.user.is_superuser = True
        request.user.save()
        return HttpResponse('You are now staff+superuser', content_type='text/plain', status=200)

        

