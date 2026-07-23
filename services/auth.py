import json
import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import click
from flask import current_app
from flask.cli import AppGroup
from werkzeug.security import check_password_hash, generate_password_hash


VALID_ROLES = {'admin', 'viewer'}
MINIMUM_PASSWORD_LENGTH = 12
_DUMMY_PASSWORD_HASH = generate_password_hash(
    'invalid-password-placeholder',
    method='scrypt',
)


@dataclass
class User:
    id: str
    username: str
    display_name: str
    password_hash: str
    role: str
    active: bool
    created_at: str
    last_login_at: str | None = None
    session_version: int = 1

    @property
    def is_active(self):
        return self.active

    @property
    def is_authenticated(self):
        return self.active

    @property
    def is_anonymous(self):
        return False

    @property
    def is_admin(self):
        return self.role == 'admin'

    def get_id(self):
        return self.id


class AnonymousUser:
    id = None
    username = ''
    display_name = ''
    role = ''
    active = False
    session_version = 0
    is_active = False
    is_authenticated = False
    is_anonymous = True
    is_admin = False


def normalize_username(username):
    return str(username or '').strip().lower()


def validate_username(username):
    normalized = normalize_username(username)
    if not 3 <= len(normalized) <= 64:
        raise ValueError('Username must be between 3 and 64 characters.')
    if not all(character.isalnum() or character in '._-' for character in normalized):
        raise ValueError('Username may only contain letters, numbers, periods, dashes, and underscores.')
    return normalized


def validate_password(password):
    if len(password or '') < MINIMUM_PASSWORD_LENGTH:
        raise ValueError(f'Password must be at least {MINIMUM_PASSWORD_LENGTH} characters.')
    if len(password) > 128:
        raise ValueError('Password must be 128 characters or fewer.')
    return password


class AuthStore:
    def __init__(self, database_path):
        self.database_path = database_path

    def _connect(self):
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys = ON')
        return connection

    def initialize(self):
        os.makedirs(os.path.dirname(self.database_path) or '.', exist_ok=True)
        with self._connect() as connection:
            connection.execute('PRAGMA journal_mode = WAL')
            connection.executescript(
                '''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT,
                    session_version INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    actor_user_id TEXT,
                    actor_username TEXT,
                    event_type TEXT NOT NULL,
                    target TEXT,
                    details TEXT NOT NULL DEFAULT '{}',
                    remote_address TEXT,
                    FOREIGN KEY (actor_user_id) REFERENCES users(id) ON DELETE SET NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
                ON audit_events(created_at DESC);
                '''
            )
            columns = {
                row['name']
                for row in connection.execute('PRAGMA table_info(users)').fetchall()
            }
            if 'session_version' not in columns:
                connection.execute(
                    'ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 1'
                )

    @staticmethod
    def _user_from_row(row):
        if row is None:
            return None
        return User(
            id=row['id'],
            username=row['username'],
            display_name=row['display_name'],
            password_hash=row['password_hash'],
            role=row['role'],
            active=bool(row['active']),
            created_at=row['created_at'],
            last_login_at=row['last_login_at'],
            session_version=row['session_version'],
        )

    def has_users(self):
        with self._connect() as connection:
            return connection.execute('SELECT 1 FROM users LIMIT 1').fetchone() is not None

    def count_active_admins(self):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) AS count FROM users WHERE role = 'admin' AND active = 1"
            ).fetchone()
            return row['count']

    def list_users(self):
        with self._connect() as connection:
            rows = connection.execute(
                'SELECT * FROM users ORDER BY role, username'
            ).fetchall()
        return [self._user_from_row(row) for row in rows]

    def get_user(self, user_id):
        with self._connect() as connection:
            row = connection.execute('SELECT * FROM users WHERE id = ?', (str(user_id),)).fetchone()
        return self._user_from_row(row)

    def get_by_username(self, username):
        with self._connect() as connection:
            row = connection.execute(
                'SELECT * FROM users WHERE username = ? COLLATE NOCASE',
                (normalize_username(username),),
            ).fetchone()
        return self._user_from_row(row)

    def create_user(self, username, password, display_name='', role='viewer'):
        username = validate_username(username)
        password = validate_password(password)
        if role not in VALID_ROLES:
            raise ValueError('Choose a valid account role.')
        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        user_id = str(uuid.uuid4())
        display_name = str(display_name or '').strip() or username
        if len(display_name) > 80:
            raise ValueError('Display name must be 80 characters or fewer.')
        try:
            with self._connect() as connection:
                connection.execute(
                    '''
                    INSERT INTO users
                    (id, username, display_name, password_hash, role, active, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?)
                    ''',
                    (
                        user_id,
                        username,
                        display_name,
                        generate_password_hash(password, method='scrypt'),
                        role,
                        now,
                    ),
                )
        except sqlite3.IntegrityError as error:
            raise ValueError('That username is already in use.') from error
        return self.get_user(user_id)

    def create_initial_admin(self, username, password, display_name=''):
        username = validate_username(username)
        password = validate_password(password)
        display_name = str(display_name or '').strip() or username
        if len(display_name) > 80:
            raise ValueError('Display name must be 80 characters or fewer.')
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        with self._connect() as connection:
            connection.execute('BEGIN IMMEDIATE')
            if connection.execute('SELECT 1 FROM users LIMIT 1').fetchone():
                raise ValueError('Administrator setup has already been completed.')
            connection.execute(
                '''
                INSERT INTO users
                (id, username, display_name, password_hash, role, active, created_at)
                VALUES (?, ?, ?, ?, 'admin', 1, ?)
                ''',
                (
                    user_id,
                    username,
                    display_name,
                    generate_password_hash(password, method='scrypt'),
                    now,
                ),
            )
        return self.get_user(user_id)

    def verify_user(self, username, password):
        user = self.get_by_username(username)
        if not user or not user.active:
            check_password_hash(_DUMMY_PASSWORD_HASH, password or '')
            return None
        if not check_password_hash(user.password_hash, password or ''):
            return None
        return user

    def set_password(self, user_id, password):
        password = validate_password(password)
        with self._connect() as connection:
            connection.execute(
                '''
                UPDATE users
                SET password_hash = ?, session_version = session_version + 1
                WHERE id = ?
                ''',
                (generate_password_hash(password, method='scrypt'), str(user_id)),
            )

    def set_active(self, user_id, active):
        with self._connect() as connection:
            connection.execute(
                '''
                UPDATE users
                SET active = ?, session_version = session_version + 1
                WHERE id = ?
                ''',
                (1 if active else 0, str(user_id)),
            )

    def record_login(self, user_id):
        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        with self._connect() as connection:
            connection.execute(
                'UPDATE users SET last_login_at = ? WHERE id = ?',
                (now, str(user_id)),
            )

    def add_audit_event(
        self,
        event_type,
        actor=None,
        target=None,
        details=None,
        remote_address=None,
        actor_username=None,
    ):
        now = datetime.now(timezone.utc).isoformat(timespec='seconds')
        with self._connect() as connection:
            connection.execute(
                '''
                INSERT INTO audit_events
                (created_at, actor_user_id, actor_username, event_type, target, details, remote_address)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    now,
                    getattr(actor, 'id', None),
                    actor_username or getattr(actor, 'username', None),
                    event_type,
                    target,
                    json.dumps(details or {}, separators=(',', ':')),
                    remote_address,
                ),
            )

    def list_audit_events(self, limit=100):
        limit = max(1, min(int(limit), 500))
        with self._connect() as connection:
            rows = connection.execute(
                'SELECT * FROM audit_events ORDER BY id DESC LIMIT ?',
                (limit,),
            ).fetchall()
        return [dict(row) | {'details': json.loads(row['details'])} for row in rows]


auth_cli = AppGroup('auth', help='Manage local LumenTrace accounts.')


@auth_cli.command('list-users')
def list_users_command():
    for user in current_app.auth_store.list_users():
        state = 'active' if user.active else 'disabled'
        click.echo(f'{user.username}\t{user.role}\t{state}')


@auth_cli.command('create-user')
@click.option('--username', prompt=True)
@click.option('--display-name', default='')
@click.option('--role', type=click.Choice(sorted(VALID_ROLES)), default='viewer')
@click.password_option(confirmation_prompt=True)
def create_user_command(username, display_name, role, password):
    try:
        user = current_app.auth_store.create_user(username, password, display_name, role)
    except ValueError as error:
        raise click.ClickException(str(error)) from error
    current_app.auth_store.add_audit_event(
        'account.created_cli',
        target=user.username,
        details={'role': user.role},
    )
    click.echo(f'Created {user.role} account {user.username}.')


@auth_cli.command('reset-password')
@click.argument('username')
@click.password_option(confirmation_prompt=True)
def reset_password_command(username, password):
    user = current_app.auth_store.get_by_username(username)
    if not user:
        raise click.ClickException('User not found.')
    try:
        current_app.auth_store.set_password(user.id, password)
    except ValueError as error:
        raise click.ClickException(str(error)) from error
    current_app.auth_store.add_audit_event('account.password_reset_cli', target=user.username)
    click.echo(f'Reset password for {user.username}.')
