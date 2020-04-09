import uuid
import pytz
from django.db import models
from django.dispatch import receiver
from django.urls import reverse
from django.contrib.auth.models import User
from django.db.models.signals import post_save, post_delete
from django.contrib.auth import get_user_model
import datetime as dt
#from django.core.signals import p

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

class LogEntry(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, related_name='+',
        null=True)
    task = models.ForeignKey(Task, on_delete=models.CASCADE, related_name='entries')
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    date = models.DateField(default=dt.date.today)
    comment = models.CharField(max_length=100, blank=True)

    def __str__(self):
        return f"{self.user} did '{self.task}' at {self.timestamp}"

    class Meta:
        ordering = ['-date', '-timestamp']

class Membership(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    task = models.ForeignKey(Task, on_delete=models.CASCADE)
    # gifted_turns = models.IntegerField(default=0)
    # keep track of turn counts to reduce db accesses
    # setting this to -1 will trigger an actual count via the LogEntries
    turn_count = models.IntegerField(default=-1)

    def get_turn_count(self):
        if self.turn_count == -1:
            # Update
            count = LogEntry.objects.filter(user=self.user, task=self.task).count()
            self.turn_count = count
            self.save()

        return self.turn_count

    # automatically update turn count
    @staticmethod
    @receiver(post_save, sender=LogEntry)
    def on_logentry_save(**kwargs):
        if kwargs.get('created'):
            # initialize or increment the turn_count
            task = kwargs.get('instance').task
            user = kwargs.get('instance').user
            memb = Membership.objects.get(user=user, task=task)
            if memb.turn_count == -1:
                # Actually count
                count = LogEntry.objects.filter(user=user, task=task).count()
                memb.turn_count = count
            else:
                memb.turn_count += 1

            memb.save()
        else:
            # recalculate all turn counts, since entry may have belonged to
            # other task prior
            user = kwargs.get('instance').user
            memb = Membership.objects.filter(user=user)
            for _ in memb:
                _.turn_count = -1
                _.save()

    @staticmethod
    @receiver(post_delete, sender=LogEntry)
    def on_logentry_delete(**kwargs):
        inst = kwargs.get('instance')
        memb = Membership.objects.get(user=inst.user, task=inst.task)
        if memb.turn_count == -1:
            # Actually count
            count = LogEntry.objects.filter(user=inst.user, task=inst.task).count()
            memb.turn_count = count
        else:
            memb.turn_count -= 1
        memb.save()


class UserSettings(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='settings')
    timezone = models.CharField(max_length=50, default='UTC', choices=[
        (_, _) for _ in pytz.common_timezones
    ])

class Invite(models.Model):
    task = models.ForeignKey(Task, on_delete=models.CASCADE)
    token = models.CharField(max_length=22) # 16 bytes of randomness base64-encoded
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['timestamp'] # oldest first

class PasswordReset(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    token = models.CharField(max_length=43) # 32 bytes of randomness base64-encoded
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ['timestamp'] # oldest first
