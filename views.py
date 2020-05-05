from django.shortcuts import render, get_object_or_404
from django.template.loader import render_to_string
from django.urls import reverse_lazy, reverse
from django.views.generic import TemplateView, FormView, View
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.models import Group, User
from django.contrib.auth.forms import PasswordChangeForm, SetPasswordForm
from django.contrib.auth.mixins import UserPassesTestMixin
from django.http.response import HttpResponseRedirect, HttpResponseForbidden
from django.core.mail import EmailMultiAlternatives
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from django.utils import timezone

from datetime import datetime, timedelta
from secrets import token_urlsafe
from ratelimit.decorators import ratelimit

import pytz


# from django.contrib.auth.forms import AuthenticationForm
# from django.contrib.auth.forms import UserCreationForm
from .forms import (
    CaptchaForm, FullUserCreationForm, UserSettingsForm, UserDetailsForm,
    CustomAuthenticationForm, TaskForm, TaskInviteForm, LogEntryForm,
    PasswordResetStartForm)
from .models import (
    UserSettings, Task, Invite, LogEntry, Membership,
    PasswordReset)
from .constants import (
    APP_GROUP_NAME, INVITE_TOKEN_KEY,
    PASSWORD_RESET_TOKEN_LIFESPAN, INVITE_TOKEN_LIFESPAN)
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

def expire_reset_tokens():
    expiry_time = timezone.now() - timedelta(days=PASSWORD_RESET_TOKEN_LIFESPAN)
    PasswordReset.objects.filter(timestamp__lt=expiry_time).delete()

def expire_invite_tokens():
    expiry_time = timezone.now() - timedelta(days=INVITE_TOKEN_LIFESPAN)
    Invite.objects.filter(timestamp__lt=expiry_time).delete()

def send_invites(user, task, recipients):
    expire_invite_tokens()
    base_context = {
        'user': user,
        'task': task,
    }

    # TODO: Remove any invites more than a week old

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
            subject="Invitation to a shared task on Whose Turn Is It",
            body=txt_message,
            from_email=f'"Whose Turn Is It" <{settings.WHOSETURNISIT_EMAIL}>',
            to=[recipient],
        )
        message.attach_alternative(html_message, 'text/html')
        message.send()

def send_password_reset(user, email):
    expire_reset_tokens()
    token = token_urlsafe(32)
    reset_url = settings.SITE_URL + reverse('wt-passwordresetfinish',
                                            kwargs={'token': token})

    # TODO: Remove any previous resets that are more than an hour old

    reset = PasswordReset()
    reset.user = user
    reset.token = token
    reset.save()

    html_message = render_to_string('whoseturn/password_reset_email.html',
        {'reset_url': reset_url, 'use_html': True})
    txt_message = render_to_string('whoseturn/password_reset_email.html',
        {'reset_url': reset_url, 'use_html': False})
    message = EmailMultiAlternatives(
        subject="Whose Turn Is It : Password Reset",
        body=txt_message,
        from_email=f'Whose Turn Is It <{settings.WHOSETURNISIT_EMAIL}>',
        to=[email]
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
        membership = Membership.objects.get(user=user, task=task)
        count = membership.get_turn_count()
        turns[user.username] = count

    return turns


class LoginView(View):
    template_name = 'whoseturn/login.html'
    error_template = 'whoseturn/generic_error.html'
    form_class = CustomAuthenticationForm
    success_url = reverse_lazy('wt-dashboard')
    test_func = logged_in_test

    def get(self, request, **kwargs):
        if self.test_func():
            return HttpResponseRedirect(self.success_url)
        else:
            form = CustomAuthenticationForm()
            return render(request, self.template_name, {'form': form})

    @ratelimit(key='user_or_ip', rate='30/h', method='POST')
    @ratelimit(key='user_or_ip', rate='5/m', method='POST')
    def post(self, request, **kwargs):
        if getattr(request, 'limited', False):
            return render(request, self.error_template, {
                'message': """
                    We've noticed a large number of attempts to login as the same username.
                    Please wait a few minutes to try again. If you can't remember your password,
                    use the password reset feature.
                """
            })

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
            'captcha_form': CaptchaForm(),
        })
        return context

    def post(self, request, **kwargs):
        user_form = FullUserCreationForm(request.POST)
        settings_form = UserSettingsForm(request.POST)
        captcha_form = CaptchaForm(request.POST)
        if user_form.is_valid() and settings_form.is_valid() and captcha_form.is_valid():
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
                'captcha_form': captcha_form,
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
    error_template = 'whoseturn/generic_error.html'

    def get(self, request, **kwargs):
        if self.test_func():
            # user is logged in and member of app

            # check for pending invite
            invite_token = request.session.get(INVITE_TOKEN_KEY, None)
            if invite_token is not None:
                try:
                    invite = Invite.objects.get(token=invite_token)
                except ObjectDoesNotExist:
                    invite = None

                del request.session[INVITE_TOKEN_KEY]
                if invite is not None:
                    task = invite.task
                    turns = get_member_turns(task)
                    max_turns = max(turns.values())
                    task.members.add(request.user)
                    membership = Membership.objects.get(task=task, user=request.user)
                    membership.turn_count = max_turns
                    membership.save()
                    invite.delete()
                else:
                    return render(request, self.error_template,
                    {'message': 'Invite does not exist or has expired.'
                    ' Ask your buddy to another and keep in '
                    f'mind, they only last {INVITE_TOKEN_LIFESPAN} days!'})

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

        least_frequent_users = set()
        least_frequent_turns = 0
        for username in turns:
            if not least_frequent_users:
                least_frequent_users.add(username)
                least_frequent_turns = turns[username]
                continue

            if turns[username] == least_frequent_turns:
                least_frequent_users.add(username)
                continue

            if turns[username] < least_frequent_turns:
                least_frequent_turns = turns[username]
                least_frequent_users = set([username])

        if len(least_frequent_users) == 1 or least_frequent_turns == 0:
            return next(iter(least_frequent_users))



        # Here there are >1 LFUs and they've all gone >0 times
        # Return the one that went least recently
        # timestamps are ordered by -timestamp, so most recent entry sould be first
        earliest_time = None
        least_recent_user = None
        for username in sorted(list(least_frequent_users)):
            user = User.objects.get(username=username)
            latest_entry = LogEntry.objects.filter(task=task, user=user)[:1]

            # Corner case: a user is here because of only gifted turns, but has
            # no real logentry in the db. If we encounter such a user, we
            # simply choose them, there's no way to rationally perfer anyone
            # else.
            if not latest_entry:
                return username

            latest_entry = latest_entry[0]
            if earliest_time is None or latest_entry.timestamp < earliest_time:
                earliest_time = latest_entry.timestamp
                least_recent_user = username

        return least_recent_user

class NewTaskView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/task_new.html'
    success_template = 'whoseturn/generic_success.html'
    error_template = 'whoseturn/generic_error.html'

    def get_context_data(self, **kwargs):
        context = {
            'form': TaskForm(),
            'invite_lifespan': INVITE_TOKEN_LIFESPAN,
        }
        return context;

    @ratelimit(key='user_or_ip', rate='30/h', method='POST')
    @ratelimit(key='user_or_ip', rate='5/m', method='POST')
    def post(self, request, **kwargs):
        if getattr(request, 'limited', False):
            return render(request, self.error_template, {
                'message': """
                    You're adding a lot of new group tasks at once. Please wait a few minutes before adding more.
                """
            })

        form = TaskForm(request.POST)
        captcha_form = CaptchaForm(request.POST)
        if form.is_valid():
            self.form_valid(form) # write to self.new_object
            return render(self.request, self.success_template,
                {'redirect_url': reverse('wt-dashboard'),
                 'message': 'New task group created!'})
        else:
            context = {
                'form': form,
                'invite_lifespan': INVITE_TOKEN_LIFESPAN,
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
    error_template = 'whoseturn/generic_error.html'

    def get_context_data(self, **kwargs):
        task = get_object_or_404(Task, id=kwargs['task_id'],
                                       members__username=self.request.user.username)

        context = {
            'form': TaskInviteForm(),
            'invite_lifespan': INVITE_TOKEN_LIFESPAN,
        }
        return context

    @ratelimit(key='user_or_ip', rate='30/h', method='POST')
    @ratelimit(key='user_or_ip', rate='5/m', method='POST')
    def post(self, request, **kwargs):
        if getattr(request, 'limited', False):
            return render(request, self.error_template, {
                'message': """
                    You're sending out an awful lot of invites at once. Please wait a few minutes before sending more.
                """
            })

        task = get_object_or_404(Task, id=kwargs['task_id'],
                                       members__username=request.user.username)
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
            return render(request, self.template_name, {'form': form, 'invite_lifespan': INVITE_TOKEN_LIFESPAN})

class TaskDeleteView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/task_delete.html'
    success_template = 'whoseturn/generic_success.html'

    def get_context_data(self, **kwargs):
        task = get_object_or_404(Task, id=kwargs['task_id'],
                                 members__username=self.request.user.username)
        context = {
            'task': task,
        }
        return context

    def post(self, request, **kwargs):
        task = get_object_or_404(Task, id=kwargs['task_id'],
                                 members__username=self.request.user.username)
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
        expire_invite_tokens()
        invite = get_object_or_404(Invite, token=kwargs['token'])

        # invite is valid
        request.session[INVITE_TOKEN_KEY] = kwargs['token']
        return HttpResponseRedirect(reverse('wt-dashboard'))

class NewEntryView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/entry_new.html'
    success_template = 'whoseturn/generic_success.html'
    error_template = 'whoseturn/generic_error.html'

    def dispatch(self, request, **kwargs):
        tzname = request.user.settings.timezone
        if tzname:
            timezone.activate(pytz.timezone(tzname))
        return super().dispatch(request, **kwargs)

    def get_context_data(self, **kwargs):
        task_id = kwargs.get('task_id', None)
        task = None
        if task_id is not None:
            task = get_object_or_404(Task, id=task_id, members__username=self.request.user.username)

        form = LogEntryForm(init_user=self.request.user, initial={'task': task})

        context = {'form': form}
        return context

    @ratelimit(key='user_or_ip', rate='60/h', method='POST')
    @ratelimit(key='user_or_ip', rate='6/m', method='POST')
    def post(self, request, **kwargs):
        if getattr(request, 'limited', False):
            return render(request, self.error_template, {
                'message': """
                    You're adding an awful log of entries at once. Please wait a few minutes before adding more.
                """
            })

        form = LogEntryForm(request.POST, init_user=request.user)
        if form.is_valid():
            self.form_valid(form)
            return render(request, self.success_template,
                {'redirect_url': reverse('wt-logentrylist', kwargs={'task_id': form.cleaned_data['task'].id}),
                 'message': "Your contribution has been noted!"})
        else:
            return render(request, self.template_name, {'form': form})

    def form_valid(self, form):
        #task = get_object_or_404(Task, id=form.cleaned_data['task'].id, members__username=self.request.user.username)
        entry = form.save(commit=False)
        entry.user = self.request.user
        entry.save() # membership automatically updated
        return

class EntryEditView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/entry_edit.html'
    success_template = 'whoseturn/generic_success.html'

    def dispatch(self, request, **kwargs):
        tzname = request.user.settings.timezone
        if tzname:
            timezone.activate(pytz.timezone(tzname))
        return super().dispatch(request, **kwargs)

    def get_context_data(self, **kwargs):
        entry = get_object_or_404(LogEntry,
                                  id=kwargs['entry_id'],
                                  user=self.request.user)
        form = LogEntryForm(init_user=self.request.user, instance=entry)
        context = {
            'entry': entry,
            'form': form
        }
        return context

    def post(self, request, **kwargs):
        entry = get_object_or_404(LogEntry,
                                  id=kwargs['entry_id'],
                                  user=self.request.user)

        form = LogEntryForm(request.POST, init_user=request.user, instance=entry)
        if form.is_valid():
            self.form_valid(form)
            return render(request, self.success_template,
                {'redirect_url': reverse('wt-logentrylist', kwargs={'task_id': entry.task.id}),
                 'message': "Changes have been saved!"})
        else:
            return render(request, self.template_name, {'entry': entry, 'form': form})

    def form_valid(self, form):
        entry = form.save(commit=False)
        entry.user = self.request.user
        entry.save() # membership automatically updated
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
        task = get_object_or_404(Task, id=kwargs['task_id'],
                                 members__username=self.request.user.username)
        turns = get_member_turns(task)

        context = {
            'task': task,
            'user': self.request.user,
            'member_count': len(turns),
            'member_list': sorted([
                {'user': task.members.get(username=_),
                 'turn_count': turns[_]}
                for _ in turns
            ], key=lambda x:x['turn_count']),
            'entries': task.entries.all(),
        }
        return context

class EntryDeleteView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/entry_delete.html'
    success_template = 'whoseturn/generic_success.html'

    def get_context_data(self, **kwargs):
        entry = get_object_or_404(LogEntry,
                                 id=kwargs['entry_id'],
                                 user=self.request.user)
        context = {
            'entry': entry,
        }
        return context

    def post(self, request, **kwargs):
        entry = get_object_or_404(LogEntry,
                                 id=kwargs['entry_id'],
                                 user=self.request.user)
        task = entry.task
        confirm = request.POST.get('confirm')
        if confirm == 'confirm':
            entry.delete()
            context = {
                'redirect_url': reverse('wt-logentrylist', kwargs={'task_id': task.id}),
                'message': "Entry deleted!"
            }
            return render(request, self.success_template, context)
        else:
            return HttpResponseRedirect(reverse('wt-logentrylist', kwargs={'task_id': task.id}))

class SettingsView(UserPassesTestMixin, TemplateView):
    test_func = logged_in_test
    template_name = 'whoseturn/settings.html'
    success_template = 'whoseturn/generic_success.html'

    def get_context_data(self, **kwargs):
        context = {
            'settings_form': UserSettingsForm(instance=self.request.user.settings),
            'details_form': UserDetailsForm(instance=self.request.user),
            'password_change_form': PasswordChangeForm(self.request.user),
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
        elif form_name == 'password_change':
            form = PasswordChangeForm(request.user, request.POST)
            if form.is_valid():
                form.save()
                update_session_auth_hash(request, request.user)
                context['updated_info'] = 'password'
            context['password_change_form'] = form

        return render(request, self.template_name, context)

class PasswordResetView(View):
    start_template = 'whoseturn/password_reset_start.html'
    finish_template = 'whoseturn/password_reset_finish.html'
    success_template = 'whoseturn/generic_success.html'
    error_template = 'whoseturn/generic_error.html'

    def get(self, request, **kwargs):
        token = kwargs.get('token', None)

        if token is None:
            # Start Process
            form = PasswordResetStartForm()
            captcha_form = CaptchaForm()
            return render(request, self.start_template,
                {'form': form, 'captcha_form': captcha_form, 'reset_lifespan': PASSWORD_RESET_TOKEN_LIFESPAN})
        else:
            expire_reset_tokens()
            # Test token validity and display setpasswordform
            try:
                reset = PasswordReset.objects.get(token=token)
            except ObjectDoesNotExist:
                reset = None

            if reset is not None:
                form = SetPasswordForm(reset.user)
                return render(request, self.finish_template,
                    {'form': form, 'user': reset.user})
            else:
                return render(request, self.error_template,
                    {'message': 'Reset token does not exist or has expired.'})

    def post(self, request, **kwargs):
        token = kwargs.get('token', None)
        if token is None:
            # Send reset email
            form = PasswordResetStartForm(request.POST)
            captcha_form = CaptchaForm(request.POST)
            if form.is_valid() and captcha_form.is_valid():
                try:
                    user = User.objects.get(username=form.cleaned_data.get('username'))
                except ObjectDoesNotExist:
                    user = None

                if user is None:
                    return render(request, self.error_template,
                        {'message': 'Username not found, please verify you typed it correctly.'})
                else:
                    email = user.email
                    send_password_reset(user, email)
                    return render(request, self.success_template,
                        {
                            'redirect_url': reverse('wt-login'),
                            'message': 'Password reset email sent.'
                        })
            else:
                return render(request, self.start_template, 
                    {
                        'form': form ,
                        'captcha_form': captcha_form, 
                        'reset_lifespan': PASSWORD_RESET_TOKEN_LIFESPAN
                    })
        else:
            # reset password
            reset = get_object_or_404(PasswordReset, token=token)
            form = SetPasswordForm(reset.user, request.POST)
            if form.is_valid():
                form.save()
                return render(request, self.success_template,
                    {
                        'redirect_url': reverse('wt-login'),
                        'message': 'Password successfully reset!',
                    })
            else:
                return render(request, self.finish_template,
                    {'form': form, 'user': reset.user})
