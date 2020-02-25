from django.contrib import admin
from .models import UserSettings, LogEntry, Task, Invite
# Register your models here.

admin.site.register(UserSettings)
admin.site.register(LogEntry)
admin.site.register(Task)
admin.site.register(Invite)
