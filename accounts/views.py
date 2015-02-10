from django.shortcuts import render, get_object_or_404, redirect
from django.conf import settings
from django.contrib.sessions.models import Session
from django.contrib.auth import get_user_model
from models import EmailVerification
from django.utils import timezone
from django.http.response import Http404, HttpResponseRedirect
from django.contrib.auth import authenticate, login
from django.core.urlresolvers import reverse
from forms import SignUpForm, ForgotPasswordForm,\
    ResetPasswordForm, SocialAccountConfirmForm
from django.template.loader import get_template
from django.template.context import Context
from django.contrib.auth.decorators import login_required
from actions import apply_user_permissions, send_password_reset_email,\
    send_social_auth_provider_login_email


def index(request):
    """Serve up the primary account view, or the login view if not logged in
    """
    if request.user.is_anonymous():
        return login_page(request)
    
    c = {}

    if settings.DEBUG:
        c['users'] = get_user_model().objects.all()
        c['sessions'] = all_logged_in_users()

    return render(request, 'accounts/index.html', c)


def login_page(request):
    """The login view. Served from index()
    """
    next_page = request.GET.get('next', '/')
    c = {}
    
    if request.method == 'POST': 
        # Try a user/pw login
        u = request.POST['username']
        p = request.POST['password']
        user = authenticate(username=u, password=p)
        if user is not None: 
            if user.is_active:
                login(request, user)
                return HttpResponseRedirect(next_page)
            else:
                return HttpResponse("Access Denied", status=403)
        else:
            return render(request, 'accounts/invalid_credentials.html')

    c = dict(GPLUS_ID=settings.SOCIAL_AUTH_GOOGLE_PLUS_KEY, 
             GPLUS_SCOPE=' '.join(settings.SOCIAL_AUTH_GOOGLE_PLUS_SCOPES),
             next=next_page)
    
    return render(request, 'accounts/login.html', c)


def register(request):
    """Show the registration page.
    """
    
    if not request.user.is_anonymous():
        return HttpResponseRedirect('/')
    
    if request.method == 'POST': 
        form = SignUpForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            user, created = get_user_model().objects.get_or_create(username=username)
            if not created: 
                # This may happen if the form is submitted outside the normal
                # login flow with a user that already exists
                return render(request, 'accounts/registration_error.html')

            user.is_active = False  # not validated yet
            user.set_password(password)
            user.first_name = first_name
            user.last_name = last_name
            user.email = email
           
            user.save()

            apply_user_permissions(user)
            verify_email_address(request, user)
            
            return render(request, 'accounts/check_your_email.html')
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
        form = SocialAccountConfirmForm({
            # create the form with defaults from the auth provider
            'email': data['kwargs']['details'].get('email', ''),
            'real_name': data['kwargs']['details'].get('fullname', ''),
            'preferred_name': data['kwargs']['details'].get('first_name', ''),
        })

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
    """

    # TODO: Store this with the user itself
    # This is a temporary hack to get around having to create a new 
    # user model right now. The problem with this is that the code is 
    # stored in the current session, so use must the same browser 
    # session to validate your email address. In most cases that's 
    # probably fine, but in many cases it won't work. 
    
    e = EmailVerification()
    e.user = user
    e.email_to_verify = user.email
    e.activate_user = activate_user
    e.save()
    send_verification_email(request, e)


def send_verification_email(request, e):
    """Send a verification link to the specified user.
    """
    
    url = request.build_absolute_uri(reverse('account:verify_email', 
                                             args=(e.verification_code,)))
    
    context = Context({'name': e.user.get_short_name(), 'url': url})
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
                user = User.objects.get(email=email, 
                                        userdata__email_verified=True)
                if user.social_auth.exists():
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
    
    if e.user.social_auth.all().exists():
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

        

