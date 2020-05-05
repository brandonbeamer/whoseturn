from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.forms import ModelForm, ValidationError, Form, PasswordInput
from django.forms.fields import CharField
from django.core.validators import validate_email
from django.contrib.auth.password_validation import validate_password
from captcha.fields import ReCaptchaField
from .constants import APP_GROUP_NAME
from .models import UserSettings, Task, LogEntry


class CaptchaForm(Form):
    captcha = ReCaptchaField()

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
    # TODO: Make name mandatory
    class Meta:
        model = User
        fields = ['first_name', 'email', 'username']

class UserDetailsForm(ModelForm):
    # TODO: Make name mandatory
    class Meta:
        model = User
        fields = ['first_name', 'email']

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
    invite_emails = EmailListField(max_length=300, required=False)
    class Meta:
        model = Task
        fields = ['name']

class TaskInviteForm(Form):
    invite_emails = EmailListField(max_length=300, required=True)


class LogEntryForm(ModelForm):
    def __init__(self, *args, init_user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance:
            self.fields['task'].queryset = init_user.task_set

    class Meta:
        model = LogEntry
        fields = ['task', 'date', 'comment']

class PasswordResetStartForm(Form):
    username = CharField(max_length=150)

# class PasswordResetFinishForm(Form):
#     def __init__(self, user, postdata=None):
#         super().__init__(postdata)
#         self.user = user
#
#     password1 = CharField(widget=PasswordInput)
#     password2 = CharField(widget=PasswordInput)
#
#     def clean_password1(self):
#         data = self.cleaned_data['recipients']
#         validate_password(data, self.user)
#         return data
#
#     def clean(self):
#         cleaned_data = super().clean()
#         pw1 = self.cleaned_data.get('password1')
#         pw2 = self.cleaned_data.get('password2')
#         if pw1 != pw2:
#             raise ValidationError("Password do not match", 'password_mismatch')
#         return
