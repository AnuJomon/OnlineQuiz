# Generated by Django 5.1.2 on 2024-10-24 05:04

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('quizapp', '0003_rename_text_question_question_text_question_category_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='quiz',
            name='duration',
            field=models.PositiveIntegerField(default=60),
        ),
    ]
