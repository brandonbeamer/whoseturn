from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.forms import ModelForm, ValidationError
from django.forms.fields import CharField
from django.core.validators import validate_email
from django import forms
from .constants import APP_GROUP_NAME
from .models import UserSettings, Task


class EmailListField(CharField):
    # No need to override consructor
    def to_python(self, value):
        if not value:
            return []
        return [_.strip() for _ in value.split(',')]

    def validate(self, value):
        super().validate(value)
        for email in value:
            validate_email(email)


class UserSettingsForm(ModelForm):
    class Meta:
        model = UserSettings
        fields = ['timezone']

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

class TaskForm(ModelForm):
    invite_emails = EmailListField(max_length=300)
    class Meta:
        model = Task
        fields = ['name']
