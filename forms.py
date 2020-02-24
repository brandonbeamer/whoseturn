from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.forms import ModelForm, ValidationError
from .constants import APP_GROUP_NAME


class FullUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'username']

class CustomAuthenticationForm(AuthenticationForm):
    def confirm_login_allowed(self, user):
        if not user.groups.filter(name=APP_GROUP_NAME).exists():
            raise ValidationError(
                "User is not a member of 'WhoseTurnIsIt' Group. "
                "She may have an account elsewhere on the this site, but "
                "needs to register with this app specifically.",
                code='missinggroup'
            )
