# Generated by Django 5.1.2 on 2024-10-18 06:57

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('quizapp', '0002_answer_category_question_participant_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='question',
            old_name='text',
            new_name='question_text',
        ),
        migrations.AddField(
            model_name='question',
            name='category',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='quizapp.category'),
        ),
        migrations.AddField(
            model_name='question',
            name='point',
            field=models.IntegerField(default=0),
        ),
    ]
