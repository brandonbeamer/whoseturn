# Generated by Django 3.0.2 on 2020-02-26 06:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('whoseturn', '0003_auto_20200226_0618'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='usersettings',
            name='gifted_turns',
        ),
    ]
