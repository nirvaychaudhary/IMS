# Generated by Django 4.0.3 on 2022-04-11 11:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('tasks', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='assigntask',
            name='finish_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='assigntask',
            name='start_date',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]