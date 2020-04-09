from django.urls import path, reverse_lazy
from django.views.generic import RedirectView
from .views import (
    RegisterView, LoginView, LogoutView,
    DashboardView,
    NewTaskView, TaskListView, TaskDeleteView, TaskInviteView,
    AcceptInviteView,
    NewEntryView, EntryListView, EntryDeleteView, EntryEditView,
    SettingsView, PasswordResetView)


urlpatterns = [
    # path('login/', Login.as_view(), name='wt-login'),
    path('login', LoginView.as_view(), name='wt-login'),
    path('logout', LogoutView.as_view(), name='wt-logout'),
    path('register', RegisterView.as_view(), name='wt-register'),
    path('dashboard', DashboardView.as_view(), name='wt-dashboard'),
    path('newtask', NewTaskView.as_view(), name='wt-newtask'),
    path('acceptinvite/<str:token>', AcceptInviteView.as_view(), name='wt-invite'),
    path('managetasks', TaskListView.as_view(), name='wt-tasklist'),
    path('invite/<uuid:task_id>', TaskInviteView.as_view(), name='wt-taskinvite'),
    path('removetask/<uuid:task_id>', TaskDeleteView.as_view(), name='wt-taskdelete'),
    path('newentry', NewEntryView.as_view(), name='wt-newentry'),
    path('log/<uuid:task_id>', EntryListView.as_view(), name='wt-logentrylist'),
    path('remove_entry/<int:entry_id>', EntryDeleteView.as_view(), name='wt-logentrydelete'),
    path('edit_entry/<int:entry_id>', EntryEditView.as_view(), name='wt-logentryedit'),
    path('settings', SettingsView.as_view(), name='wt-settings'),
    path('resetpassword/<str:token>', PasswordResetView.as_view(), name='wt-passwordresetfinish'),
    path('resetpassword', PasswordResetView.as_view(), name='wt-passwordresetstart'),
    path('', RedirectView.as_view(url=reverse_lazy('wt-login'))),
]
