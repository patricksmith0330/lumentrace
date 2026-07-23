import json
import os
import sqlite3
from datetime import datetime

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils.dateparse import parse_datetime
from django.utils.timezone import make_aware

from core.models import AuditEvent


def _timestamp(value):
    parsed = parse_datetime(value or '')
    if parsed is None:
        parsed = datetime.now()
    if parsed.tzinfo is None:
        parsed = make_aware(parsed)
    return parsed


class Command(BaseCommand):
    help = 'Import users and audit history from the Flask v3 beta database.'

    def handle(self, *args, **options):
        legacy_path = os.getenv(
            'LEGACY_AUTH_DB_PATH',
            str(settings.DATA_DIR / 'auth.db'),
        )
        if not os.path.exists(legacy_path):
            self.stdout.write('No legacy Flask authentication database found.')
            return

        User = get_user_model()
        if User.objects.exists():
            self.stdout.write('Django users already exist; legacy import skipped.')
            return

        connection = sqlite3.connect(legacy_path)
        connection.row_factory = sqlite3.Row
        try:
            tables = {
                row['name']
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if 'users' not in tables:
                self.stdout.write('Legacy database contains no users table.')
                return
            old_users = connection.execute('SELECT * FROM users ORDER BY created_at').fetchall()
            old_events = (
                connection.execute('SELECT * FROM audit_events ORDER BY id').fetchall()
                if 'audit_events' in tables
                else []
            )
        finally:
            connection.close()

        if not old_users:
            self.stdout.write('Legacy database contains no accounts.')
            return

        imported = {}
        with transaction.atomic():
            for row in old_users:
                user = User(
                    username=row['username'],
                    first_name=row['display_name'] or row['username'],
                    password=row['password_hash'],
                    is_active=bool(row['active']),
                    is_staff=row['role'] == 'admin',
                    is_superuser=False,
                    date_joined=_timestamp(row['created_at']),
                    last_login=_timestamp(row['last_login_at']) if row['last_login_at'] else None,
                )
                user.save()
                imported[str(row['id'])] = user

            for row in old_events:
                try:
                    details = json.loads(row['details'] or '{}')
                except json.JSONDecodeError:
                    details = {}
                event = AuditEvent.objects.create(
                    actor=imported.get(str(row['actor_user_id'])),
                    actor_username=row['actor_username'] or '',
                    event_type=row['event_type'],
                    target=row['target'] or '',
                    details=details,
                    remote_address=row['remote_address'] or None,
                )
                AuditEvent.objects.filter(pk=event.pk).update(
                    created_at=_timestamp(row['created_at'])
                )

        self.stdout.write(
            self.style.SUCCESS(
                f'Imported {len(imported)} account(s) and {len(old_events)} audit event(s).'
            )
        )
