from django.urls import path, reverse_lazy
from django.views.generic import RedirectView
from .views import RegisterView, LoginView, DashboardView, LogEntriesView


urlpatterns = [
    # path('login/', Login.as_view(), name='wt-login'),
    path('login', LoginView.as_view(), name='wt-login'),
    path('register', RegisterView.as_view(), name='wt-register'),
    path('dashboard', DashboardView.as_view(), name='wt-dashboard'),
    path('log/<uuid:id>', LogEntriesView.as_view(), name='wt-logentries'),
    path('', RedirectView.as_view(url=reverse_lazy('wt-register'))),
]
