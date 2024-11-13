# Generated by Django 5.1.2 on 2024-10-24 06:31

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('quizapp', '0004_quiz_duration'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='quiz',
            name='end_time',
        ),
        migrations.RemoveField(
            model_name='quiz',
            name='start_time',
        ),
        migrations.AddField(
            model_name='quiz',
            name='total_points',
            field=models.PositiveIntegerField(default=100),
        ),
    ]