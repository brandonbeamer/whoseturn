from django.shortcuts import render
from django.urls import reverse_lazy
from django.views.generic import TemplateView, FormView, View
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import Group
from django.contrib.auth.mixins import UserPassesTestMixin

# from django.contrib.auth.forms import AuthenticationForm
# from django.contrib.auth.forms import UserCreationForm
from .forms import FullUserCreationForm, CustomAuthenticationForm
from .constants import APP_GROUP_NAME
# Create your views here.

def logged_in_test(self):
    """
    Test function for UserPassesTestMixin

    Verifies that user is logged in and member of App Group
    """
    user = self.request.user
    if not user.is_authenticated:
        return False

    if not user.groups.filter(name=APP_GROUP_NAME).exists():
        return False

    return True


class LoginView(FormView):
    template_name = 'whoseturn/login.html'
    form_class = CustomAuthenticationForm
    success_url = reverse_lazy('wt-dashboard')

    def form_valid(self, form):
        login(self.request, form.get_user())
        return super().form_valid(form)

class RegisterView(FormView):
    template_name = 'whoseturn/register.html'
    form_class = FullUserCreationForm
    success_url = reverse_lazy('wt-login')

    def form_valid(self, form):
        # Might need to make groups
        try:
            AppGroup = Group.objects.get(name=APP_GROUP_NAME)
        except:
            AppGroup = Group(name=APP_GROUP_NAME)
            AppGroup.save()

        user = form.save(commit=True)
        user.groups.set([AppGroup])
        user.save()
        return super().form_valid(form)

class DashboardView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/dashboard.html'

class LogEntriesView(UserPassesTestMixin, TemplateView):
    def test_func(self):
        pass
        # TODO: IMPLEMENET
    pass
