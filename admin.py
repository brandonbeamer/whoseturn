from django.contrib import admin
from .models import UserSettings, LogEntry, Task, Invite, PasswordReset, Membership
# Register your models here.

admin.site.register(UserSettings)
admin.site.register(LogEntry)
admin.site.register(Task)
admin.site.register(Membership)

@admin.register(Invite)
class InviteAdmin(admin.ModelAdmin):
    readonly_fields = ('timestamp',)

@admin.register(PasswordReset)
class PasswordResetAdmin(admin.ModelAdmin):
    readonly_fields = ('timestamp',)
