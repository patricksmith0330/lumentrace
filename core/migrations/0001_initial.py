import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [('auth', '0012_alter_user_first_name_max_length')]
    operations = [
        migrations.CreateModel(
            name='AuditEvent',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True, db_index=True)),
                ('actor_username', models.CharField(blank=True, max_length=150)),
                ('event_type', models.CharField(max_length=100)),
                ('target', models.CharField(blank=True, max_length=255)),
                ('details', models.JSONField(blank=True, default=dict)),
                ('remote_address', models.GenericIPAddressField(blank=True, null=True)),
                ('actor', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='lumentrace_audit_events', to=settings.AUTH_USER_MODEL)),
            ],
            options={'ordering': ['-id']},
        ),
    ]
