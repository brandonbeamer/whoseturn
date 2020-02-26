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
from django.utils import timezone

from secrets import token_urlsafe
from collections import Counter
import pytz
from datetime import datetime

# from django.contrib.auth.forms import AuthenticationForm
# from django.contrib.auth.forms import UserCreationForm
from .forms import (
    FullUserCreationForm, UserSettingsForm, UserDetailsForm,
    CustomAuthenticationForm, TaskForm, TaskInviteForm, LogEntryForm,
    PasswordResetForm)
from .models import (
    UserSettings, Task, Invite, LogEntry, Membership,
    PasswordReset)
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

def get_member_turns(task):
    """
    Returns a dictionary {username: turn_count} for each user in task.members
    """
    entries = LogEntry.objects.filter(task=task)
    turns = {}

    for user in task.members.all():
        turns[user.username] = Membership.objects.get(user=user, task=task).gifted_turns

    for entry in entries:
        turns[entry.user.username] += 1

    return turns

# TODO: Add send_password_reset function

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
    success_template = 'whoseturn/generic_success.html'

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
                {'redirect_url': reverse('wt-dashboard'),
                 'message': 'Welcome to Whose Turn Is It!',
                })
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

        login(self.request, user)
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
                turns = get_member_turns(task)
                max_turns = max(turns.values())
                task.members.add(request.user)
                membership = Membership.objects.get(task=task, user=request.user)
                membership.gifted_turns = max_turns
                membership.save()
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
            # task: user
            'turn_list': [
                {
                    'task': task,
                    'user': task.members.get(username=self.get_next_turn(task)),
                }
                for task in task_list
            ]
        }
        return context

    def get_next_turn(self, task):
        turns = get_member_turns(task)

        least_frequent_user = None
        least_frequent_turns = 0
        for username in turns:
            if (least_frequent_user is None
                or turns[username] < least_frequent_turns):

                least_frequent_turns = turns[username]
                least_frequent_user = username

        return least_frequent_user

class NewTaskView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/task_new.html'
    success_template = 'whoseturn/generic_success.html'

    def get_context_data(self, **kwargs):
        context = {
            'form': TaskForm()
        }
        return context;

    def post(self, request, **kwargs):
        form = TaskForm(request.POST)
        if form.is_valid():
            self.form_valid(form) # write to self.new_object
            return render(self.request, self.success_template,
                {'redirect_url': reverse('wt-dashboard'),
                 'message': 'New task group created!'})
        else:
            context = {
                'form': form
            }
            return render(self.request, self.template_name, context)


    def form_valid(self, form):
        task = form.save()
        task.members.add(self.request.user)
        task.creator = self.request.user
        task.save()
        invites = form.cleaned_data['invite_emails']
        send_invites(self.request.user, task, invites)
        self.new_object = task

class TaskListView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/task_list.html'

    def get_context_data(self, **kwargs):
        context = {
            'task_list': self.request.user.task_set.all()
        }
        return context

class TaskInviteView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/task_invite.html'
    success_template = 'whoseturn/generic_success.html'

    def get_context_data(self, **kwargs):
        task = get_object_or_404(Task, id=kwargs['task_id'])
        context = {
            'form': TaskInviteForm(),
        }
        return context

    def post(self, request, **kwargs):
        task = get_object_or_404(Task, id=kwargs['task_id'])
        form = TaskInviteForm(request.POST)
        if form.is_valid():
            emails = form.cleaned_data['invite_emails']
            send_invites(request.user, task, emails)
            context = {
                'redirect_url': reverse('wt-tasklist'),
                'message': 'Invites sent!',
            }
            return render(request, self.success_template, context)
        else:
            return render(request, self.template_name, {'form': form})

class TaskDeleteView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/task_delete.html'
    success_template = 'whoseturn/generic_success.html'

    def get_context_data(self, **kwargs):
        task = get_object_or_404(Task, id=kwargs['task_id'])
        context = {
            'task': task,
        }
        return context

    def post(self, request, **kwargs):
        task = get_object_or_404(Task, id=kwargs['task_id'])
        confirm = request.POST.get('confirm')
        if confirm == 'confirm':
            task.members.remove(self.request.user)
            if not task.members.exists():
                task.delete()
            context = {
                'redirect_url': reverse('wt-tasklist'),
                'message': "You've been removed from this task."
            }
            return render(request, self.success_template, context)
        else:
            return HttpResponseRedirect(reverse('wt-tasklist'))

class AcceptInviteView(View):
    def get(self, request, **kwargs):
        invite = get_object_or_404(Invite, token=kwargs['token'])

        # invite is valid
        request.session[INVITE_TOKEN_KEY] = kwargs['token']
        return HttpResponseRedirect(reverse('wt-dashboard'))

class NewEntryView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/entry_new.html'
    success_template = 'whoseturn/generic_success.html'

    def get_context_data(self, **kwargs):
        form = LogEntryForm(self.request.user)
        context = {'form': form}
        return context

    def post(self, request, **kwargs):
        form = LogEntryForm(request.user, request.POST)
        if form.is_valid():
            self.form_valid(form)
            return render(request, self.success_template,
                {'redirect_url': reverse('wt-dashboard'),
                 'message': "Your contribution has been noted!"})
        else:
            return render(request, self.template_name, {'form': form})

    def form_valid(self, form):
        entry = form.save(commit=False)
        entry.user = self.request.user
        entry.save()
        return

class EntryListView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/entry_list.html'

    def dispatch(self, request, **kwargs):
        tzname = request.user.settings.timezone
        if tzname:
            timezone.activate(pytz.timezone(tzname))
        return super().dispatch(request, **kwargs)

    def get_context_data(self, **kwargs):
        task = get_object_or_404(Task, id=kwargs['task_id'])
        turns = get_member_turns(task)

        context = {
            'task': task,
            'member_count': len(turns),
            'member_list': sorted([
                {'user': task.members.get(username=_),
                 'turn_count': turns[_]}
                for _ in turns
            ], key=lambda x:x['turn_count']),
            'entries': task.entries.all(),
        }
        return context

class SettingsView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/settings.html'
    success_template = 'whoseturn/generic_success.html'

    def get_context_data(self, **kwargs):
        context = {
            'settings_form': UserSettingsForm(instance=self.request.user.settings),
            'details_form': UserDetailsForm(instance=self.request.user),
            # TODO: Add password reset stuff
        }
        return context

    def post(self, request, **kwargs):
        form_name = request.POST.get('form_name')
        context = self.get_context_data(**kwargs)

        if form_name == 'settings':
            form = UserSettingsForm(
                instance=request.user.settings,
                data=request.POST
            )
            if form.is_valid():
                form.save()
                context['updated_info'] = 'timezone information'

            context['settings_form'] = form

        elif form_name == 'details':
            form = UserDetailsForm(
                instance=request.user,
                data=request.POST
            )
            if form.is_valid():
                form.save()
                context['updated_info'] = 'personal details'

            context['details_form'] = form

        return render(request, self.template_name, context)

class PasswordResetView(TemplateView):
    template_name = 'whoseturn/password_reset.html'
    success_template = 'whoseturn/generic_success.html'

    def get_context_data(self, **kwargs):
        token = kwargs['token']
        reset = get_object_or_404(PasswordReset, token=token)
        form = PasswordResetForm(reset.user)
        context = {
            'form': form,
        }
        return context