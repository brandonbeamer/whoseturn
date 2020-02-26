import uuid
import pytz
from django.db import models
from django.urls import reverse
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model

class Task(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=30)
    members = models.ManyToManyField(User, through='Membership',
        through_fields=('task', 'user'))
    timestamp = models.DateTimeField(auto_now_add=True)
    creator = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='+', null=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('wt-logentries', kwargs={'uuid': self.id})

class Membership(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    task = models.ForeignKey(Task, on_delete=models.CASCADE)
    gifted_turns = models.IntegerField(default=0)

class LogEntry(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='+',
        null=True)
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='entries')
    timestamp = models.DateTimeField(auto_now_add=True)
    comment = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f"{self.user} did '{self.task}' at {self.timestamp}"

    class Meta:
        ordering = ['-timestamp']

class UserSettings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='settings')
    timezone = models.CharField(max_length=50, default='UTC', choices=[
        (_, _) for _ in pytz.common_timezones
    ])

class Invite(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE)
    token = models.CharField(max_length=22) # 16 bytes of randomness base64-encoded

class PasswordReset(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=42) # 32 bytes of randomness base64-encoded
