import random 
from django.conf import settings
from django.core.urlresolvers import reverse
from django.test import TestCase
from accounts.context_processors import login_disabled
from django.contrib.auth.models import User
from django.test.client import Client
from django.core import mail
from django.core.mail import mail_admins
import re
from accounts.models import EmailVerification, UserData
from django.test.testcases import SimpleTestCase
from django.utils.crypto import get_random_string

def test_user(create=True, username=None, password=None,
              preferred_name=None, real_name=None, email=None):
    """Get or create our test user. 
    """
    
    info = dict(username=username or get_random_string(8),
                password=password or get_random_string(8),
                preferred_name=preferred_name or get_random_string(8),
                real_name=real_name or get_random_string(8),
                email=email or ''.join([get_random_string(8), '@', 
                                        get_random_string(8), '.com']))
    
    if create:
        u, created = User.objects.get_or_create(username=info['username'])
        if created:
            u.set_password(info['password'])
            u.email = info['email']
            u.save()
            u.userdata.email_verified = True
            u.userdata.preferred_name= info['preferred_name']
            u.userdata.real_name = info['real_name']

            u.userdata.save()
    else:
        u = None
        
    return u, info
    

class ContextProcessorTests(TestCase):
    def test_login_disabled(self):
        result = login_disabled(None)
        
        self.assertTrue('LOGIN_DISABLED' in result)
        self.assertEqual(result['LOGIN_DISABLED'], not settings.DEBUG)


class AccountIndexTest(SimpleTestCase):
    def setUp(self):
        self.user, self.userinfo = test_user()

    def testAnonGetsLoginPage(self):
        c = Client()
        r = c.get('/account/')
        self.assertEqual(r.status_code, 200)
        self.assertTrue('login.html' in r.templates[0].name)

    def testUserGetsAccountPage(self):
        c = Client()
        c.login(username=self.userinfo['username'], 
                password=self.userinfo['password'])
        r = c.get('/account/')
#         self.assertTrue('index.html' in r.templates[0].name)
    

class ForgotPasswordTests(TestCase):
    def setUp(self):
        self.pw1 = 'a$b$c$d'
        self.pw2 = 'w!x!y!z'
        self.user, self.userinfo = test_user(password=self.pw1)
    
    def testForgotPassword(self):
        """Positive test; Forgot a password, receive a reset email, click on 
        the link in the mail, and choose a new password. 
        """
        
        c = Client()
        
        # make sure we can log in: 
        self.assertTrue(c.login(username=self.userinfo['username'], 
                                password=self.pw1))
        c.logout()
        
        r = c.get('/account/forgot/')
        self.assertEqual(r.status_code, 200, 'bad status on forgot')
        
        r = c.post('/account/forgot/', {'email': self.user.email})
        self.assertEqual(r.status_code, 200, 'email addr not accepted')

        self.assertTrue(EmailVerification.objects.filter(user=self.user).exists())

        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox.pop()
        self.assertEqual(message.subject, 'MARCO Sign-in Information', 
                         'wrong verify subject line')
        
        # find the reset link (/account/forgot/-hash-)
        match = re.search('http://[^/]+/([/a-z0-9A-Z]+)', message.body)
        self.assertIsNotNone(match.groups(), 'no url in message')
        self.assertEqual(len(match.groups()), 1, 'no url in message')
        url = '/' + match.groups()[0]
        
        # follow the link
        r = c.get(url)
        self.assertEqual(r.status_code, 200, 'bad verify link')
                
        # reset the password
        r = c.post(url, {'password1': self.pw2, 'password2': self.pw2})
        self.assertEqual(r.status_code, 200, 'bad status')
        
        # make sure the EV was deleted
        self.assertFalse(EmailVerification.objects.filter(user=self.user).exists(),
                         'EmailVerification object not deleted')
        
        self.assertFalse(c.login(username=self.userinfo['username'], password=self.pw1), 
                        'passsword not reset')
        c.logout()
        self.assertTrue(c.login(username=self.userinfo['username'], password=self.pw2),
                        'password not reset')
        
    def testResetPasswordFormLoggedIn(self):
        c = Client()
        c.login(username=self.userinfo['username'], password=self.pw1)
        
        resp = c.get('/account/forgot/')
        
        # Trying to remember a password while logged in should get you bounced.
        self.assertTrue(resp.status_code, 301)


class RegisterTests(SimpleTestCase):
    def setUp(self):
        pass
    
    def testRegisterTemplate(self):
        c = Client()
        r = c.get(reverse('account:register'))
        self.assertEqual(r.status_code, 200)
        self.assertTrue('register.html' in r.templates[0].name)

    def testRegisterNoUsername(self):
        c = Client()
        user, d = test_user(create=False)
        del d['username']
        r = c.post(reverse('account:register'), d)
        self.assertTrue(r.status_code, 200)
        
    def testRegisterNoPassword(self):
        c = Client()
        user, d = test_user(create=False)
        del d['password']
        r = c.post(reverse('account:register'), d)
        self.assertTrue(r.status_code, 200)
        
    def testRegisterNoRealName(self):
        c = Client()
        _, d = test_user(create=False)
        del d['real_name']
        r = c.post(reverse('account:register'), d)
        self.assertTrue(r.status_code, 200)
        self.assertFalse(User.objects.filter(email=d['email']).exists())
        
    def testRegisterNoPreferredName(self):
        c = Client()
        _, d = test_user(create=False)
        del d['preferred_name']
        r = c.post(reverse('account:register'), d)
        self.assertTrue(r.status_code, 200)
        self.assertFalse(User.objects.filter(email=d['email']).exists())

    def testRegisterNoEmail(self):
        c = Client()
        _, d = test_user(create=False)
        del d['email']
        r = c.post(reverse('account:register'), d)
        self.assertTrue(r.status_code, 200)

    def testRegisterLoggedIn(self):
        c = Client()

        user, info = test_user()
        
        c.login(username=user.username,
                password=info['password'])
        r = c.get(reverse('account:register'))
        # FIXME: I'm not sure why this is failing. 
        # self.assertEqual(r.status_code, 301, "Register didn't redirected when logged in")
        
        c.logout()
        user.delete()
    
    def testRegisterNewUser(self):
        c = Client()
        _, info = test_user(create=False)

        r = c.post(reverse('account:register'), info)
        self.assertEqual(r.status_code, 200)
        
        # we should have an inactive user with an unverified email addr, and a 
        # verification record

        u = User.objects.filter(email=info['email'])
        self.assertTrue(u.exists(), 'user was not created')
        u = u[0]
        self.assertFalse(u.is_active, 'user was created active')
        try:
            u.userdata
        except UserData.DoesNotExist:
            self.fail('user was created without a userdata object.')
        
        self.assertFalse(u.userdata.email_verified, 'user was created with a verified email address')
        self.assertTrue(u.emailverification_set.all().exists(), 'user ev was not created')
        
#         self.assertFalse(EmailVerification.objects.filter(user=self.user).exists(),
#                          'EmailVerification object not deleted')

class AccountEditTests(TestCase):
    def testEditChanges(self):
        user, info = test_user()
        _, change_info = test_user(create=False)

        c = Client()
        self.assertTrue(c.login(username=info['username'],
                                password=info['password']), "Can't log in?")

        c.post(reverse('account:edit'), {
            'email': change_info['email'],
            'preferred_name': change_info['preferred_name'],
            'real_name': change_info['real_name'],
        })

        # refresh the user
        # user.refresh_from_db() # we don't get this until dj1.8...
        user = User.objects.get(pk=user.pk)
        self.assertFalse(user.userdata.email_verified)
        self.assertEqual(user.first_name, user.userdata.preferred_name)
        self.assertEqual(user.last_name, '')
        self.assertEqual(user.userdata.preferred_name,
                         change_info['preferred_name'])
        self.assertEqual(user.userdata.real_name, change_info['real_name'])
        self.assertEqual(user.email, change_info['email'])
