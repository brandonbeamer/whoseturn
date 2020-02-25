from django.shortcuts import render, get_object_or_404
from django.template.loader import render_to_string
from django.urls import reverse_lazy, reverse
from django.views.generic import TemplateView, FormView, View
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import Group, User
from django.contrib.auth.mixins import UserPassesTestMixin
from django.http.response import HttpResponseRedirect
from django.core.mail import EmailMultiAlternatives
from django.conf import settings
from secrets import token_urlsafe

# from django.contrib.auth.forms import AuthenticationForm
# from django.contrib.auth.forms import UserCreationForm
from .forms import (
    FullUserCreationForm, UserSettingsForm, CustomAuthenticationForm,
    TaskForm)
from .models import UserSettings, Task, Invite
from .constants import APP_GROUP_NAME, INVITE_TOKEN_KEY
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


def send_invites(user, task, recipients):
    base_context = {
        'user': user,
        'task': task,
    }

    for recipient in recipients:
        token = token_urlsafe(16)
        invite_url = settings.SITE_URL + reverse('wt-invite', kwargs={'token': token})

        # Create the actual invite in the db
        Invite(task=task, token=token).save()

        html_message = render_to_string('whoseturn/invite_email.html',
            {**base_context, 'invite_url': invite_url, 'use_html': True})
        txt_message = render_to_string('whoseturn/invite_email.html',
            {**base_context, 'invite_url': invite_url, 'use_html': False})

        message = EmailMultiAlternatives(
            subject="Invitation to a shared task on WhoseTurnIsIt",
            body=txt_message,
            from_email=f'"WhoseTurnIsIt" <{settings.WHOSETURNISIT_EMAIL}>',
            to=[recipient],
        )
        message.attach_alternative(html_message, 'text/html')
        message.send()


class LoginView(View):
    template_name = 'whoseturn/login.html'
    form_class = CustomAuthenticationForm
    success_url = reverse_lazy('wt-dashboard')
    test_func = logged_in_test

    def get(self, request, **kwargs):
        if self.test_func():
            return HttpResponseRedirect(self.success_url)
        else:
            form = CustomAuthenticationForm()
            return render(request, self.template_name, {'form': form})

    def post(self, request, **kwargs):
        form = CustomAuthenticationForm(request, request.POST)
        if form.is_valid():
            self.form_valid(form)
        return HttpResponseRedirect(self.success_url)


    def form_valid(self, form):
        login(self.request, form.get_user())
        return

class LogoutView(View):
    def get(self, request, **kwargs):
        logout(request)
        return HttpResponseRedirect(reverse('wt-login'))

class RegisterView(TemplateView):
    template_name = 'whoseturn/register.html'
    success_template = 'whoseturn/register_success.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'user_form': FullUserCreationForm(),
            'settings_form': UserSettingsForm(),
        })
        return context

    def post(self, request, **kwargs):
        user_form = FullUserCreationForm(request.POST)
        settings_form = UserSettingsForm(request.POST)
        if user_form.is_valid() and settings_form.is_valid():
            self.forms_valid(user_form, settings_form)
            return render(request, self.success_template,
                {'redirect_url': reverse('wt-dashboard')})
        else:
            context = super().get_context_data(**kwargs)
            context.update({
                'user_form': user_form,
                'settings_form': settings_form,
            })
            return render(request, self.template_name, context)


    def forms_valid(self, user_form, settings_form):
        # Might need to make groups
        try:
            AppGroup = Group.objects.get(name=APP_GROUP_NAME)
        except:
            AppGroup = Group(name=APP_GROUP_NAME)
            AppGroup.save()

        user = user_form.save(commit=True)
        user.groups.set([AppGroup])
        user.save()

        settings = settings_form.save(commit=False)
        settings.user = user
        settings.save()
        return

class DashboardView(View):
    test_func = logged_in_test
    template_name = 'whoseturn/dashboard.html'

    def get(self, request, **kwargs):
        if self.test_func():
            # user is logged in and member of app

            # check for pending invite
            invite_token = request.session.get(INVITE_TOKEN_KEY, None)
            if invite_token is not None:
                # add user to task and delete invite
                invite = Invite.objects.get(token=invite_token)
                task = invite.task
                task.members.add(request.user)
                invite.delete()
                del request.session[INVITE_TOKEN_KEY]

            # render template
            context = self.get_context_data(**kwargs)
            return render(request, self.template_name, context)
        else:
            return HttpResponseRedirect(reverse('wt-login'))

    def get_context_data(self, **kwargs):
        task_list = self.request.user.task_set.all()

        context = {
            'task_list': task_list
        }
        return context

class NewTaskView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/task_new.html'
    success_template = 'whoseturn/task_new_success.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context.update({
            'form': TaskForm()
        })
        return context;

    def post(self, request, **kwargs):
        form = TaskForm(request.POST)
        if form.is_valid():
            self.form_valid(form) # write to self.new_object
            return render(self.request, self.success_template,
                {'task': self.new_object, 'redirect_url': reverse('wt-dashboard')})
        else:
            context = super().get_context_data(**kwargs)
            context.update({
                'form': form
            })
            return render(self.request, self.template_name, context)


    def form_valid(self, form):
        task = form.save()
        task.members.add(self.request.user)
        task.save()
        invites = form.cleaned_data['invite_emails']
        send_invites(self.request.user, task, invites)
        self.new_object = task

class InviteView(View):
    def get(self, request, **kwargs):
        invite = get_object_or_404(Invite, token=kwargs['token'])

        # invite is valid
        request.session[INVITE_TOKEN_KEY] = kwargs['token']
        return HttpResponseRedirect(reverse('wt-dashboard'))

class LogEntriesView(UserPassesTestMixin, TemplateView):
    def test_func(self):
        pass
        # TODO: IMPLEMENET
    pass
