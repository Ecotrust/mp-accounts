from django.test import TestCase

# Create your tests here.
class RegisterTestCase(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        User.objects.create(username='user')

    def test_register_bug(self):
        # Received an error email on registering a user "'bool' object is not callable"
        #   Issue is actually that we're following 'user.is_anonymous' with "()"
        #   But we must follow the testing Goat.
        from django.http import HttpRequest
        from django.contrib.auth.models import User
        from accounts.views import register as account_register
        request = HttpRequest()
        setattr(request, "user", User.objects.all()[0])
        account_register(request)
