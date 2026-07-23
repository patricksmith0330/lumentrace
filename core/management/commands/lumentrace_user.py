from getpass import getpass

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from core.auth_utils import audit, create_user, role_name, validate_password


class Command(BaseCommand):
    help = 'List, create, or reset LumenTrace local users.'

    def add_arguments(self, parser):
        parser.add_argument('action', choices=['list', 'create', 'reset-password'])
        parser.add_argument('username', nargs='?')
        parser.add_argument('--display-name', default='')
        parser.add_argument('--role', choices=['admin', 'viewer'], default='viewer')

    def _password(self):
        first = getpass('Password: ')
        second = getpass('Password (again): ')
        if first != second:
            raise CommandError('Passwords do not match.')
        return first

    def handle(self, *args, **options):
        User = get_user_model()
        action = options['action']
        username = options.get('username')
        if action == 'list':
            for user in User.objects.order_by('-is_staff', 'username'):
                state = 'active' if user.is_active else 'disabled'
                self.stdout.write(f'{user.username}\t{role_name(user)}\t{state}')
            return
        if not username:
            raise CommandError('A username is required for this action.')
        password = self._password()
        if action == 'create':
            try:
                user = create_user(
                    username,
                    password,
                    options['display_name'],
                    options['role'],
                )
            except ValueError as error:
                raise CommandError(str(error)) from error
            audit('account.created_cli', target=user.username, details={'role': role_name(user)})
            self.stdout.write(self.style.SUCCESS(f'Created {role_name(user)} account {user.username}.'))
            return
        try:
            user = User.objects.get(username__iexact=username)
            validate_password(password, user)
        except User.DoesNotExist as error:
            raise CommandError('User not found.') from error
        except ValueError as error:
            raise CommandError(str(error)) from error
        user.set_password(password)
        user.save(update_fields=['password'])
        audit('account.password_reset_cli', target=user.username)
        self.stdout.write(self.style.SUCCESS(f'Reset password for {user.username}.'))
