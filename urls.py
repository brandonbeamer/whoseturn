from django.urls import path, reverse_lazy
from django.views.generic import RedirectView
from .views import (
    RegisterView, LoginView, LogoutView,
    DashboardView, NewTaskView, InviteView, LogEntriesView)


urlpatterns = [
    # path('login/', Login.as_view(), name='wt-login'),
    path('login', LoginView.as_view(), name='wt-login'),
    path('logout', LogoutView.as_view(), name='wt-logout'),
    path('register', RegisterView.as_view(), name='wt-register'),
    path('dashboard', DashboardView.as_view(), name='wt-dashboard'),
    path('newtask', NewTaskView.as_view(), name='wt-newtask'),
    path('invite/<str:token>', InviteView.as_view(), name='wt-invite'),
    path('log/<uuid:id>', LogEntriesView.as_view(), name='wt-logentries'),
    path('', RedirectView.as_view(url=reverse_lazy('wt-login'))),
]
