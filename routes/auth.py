from functools import wraps
from urllib.parse import urlsplit

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.local import LocalProxy

from config import RATE_LIMITS
from extensions import limiter


auth_bp = Blueprint('auth', __name__)
current_user = LocalProxy(lambda: g.current_user)


def login_user(user):
    session.clear()
    session['user_id'] = user.id
    session['session_version'] = user.session_version
    session.permanent = True


def logout_user():
    session.clear()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_app.config['AUTH_MODE'] == 'disabled':
            return view(*args, **kwargs)
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login', next=request.full_path.rstrip('?')))
        return view(*args, **kwargs)

    return wrapped


def _safe_next_url(value):
    if not value:
        return None
    parsed = urlsplit(value)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith('/'):
        return None
    return parsed.path + (f'?{parsed.query}' if parsed.query else '')


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if current_app.config['AUTH_MODE'] != 'disabled' and not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


@auth_bp.route('/setup', methods=['GET', 'POST'])
@limiter.limit(RATE_LIMITS['setup'], methods=['POST'])
def setup():
    if current_app.config['AUTH_MODE'] == 'disabled':
        return redirect(url_for('dashboard.dashboard'))
    if current_app.auth_store.has_users():
        return redirect(url_for('auth.login'))

    if request.method == 'POST':
        password = request.form.get('password', '')
        if password != request.form.get('password_confirm', ''):
            flash('Passwords do not match.', 'error')
        else:
            try:
                user = current_app.auth_store.create_initial_admin(
                    request.form.get('username', ''),
                    password,
                    request.form.get('display_name', ''),
                )
            except ValueError as error:
                flash(str(error), 'error')
            else:
                login_user(user)
                current_app.auth_store.record_login(user.id)
                current_app.auth_store.add_audit_event(
                    'account.initial_admin_created',
                    actor=user,
                    target=user.username,
                    remote_address=request.remote_addr,
                )
                flash('Administrator account created.', 'success')
                return redirect(url_for('dashboard.dashboard'))

    return render_template('auth/setup.html')


@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit(RATE_LIMITS['login'], methods=['POST'])
def login():
    if current_app.config['AUTH_MODE'] == 'disabled':
        return redirect(url_for('dashboard.dashboard'))
    if not current_app.auth_store.has_users():
        return redirect(url_for('auth.setup'))
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.dashboard'))

    next_url = _safe_next_url(request.args.get('next') or request.form.get('next'))
    if request.method == 'POST':
        username = request.form.get('username', '')
        user = current_app.auth_store.verify_user(username, request.form.get('password', ''))
        if user:
            login_user(user)
            current_app.auth_store.record_login(user.id)
            current_app.auth_store.add_audit_event(
                'auth.login_succeeded',
                actor=user,
                remote_address=request.remote_addr,
            )
            return redirect(next_url or url_for('dashboard.dashboard'))

        current_app.auth_store.add_audit_event(
            'auth.login_failed',
            actor_username=str(username).strip().lower()[:64],
            remote_address=request.remote_addr,
        )
        flash('The username or password is incorrect.', 'error')

    return render_template('auth/login.html', next_url=next_url)


@auth_bp.post('/logout')
@login_required
def logout():
    current_app.auth_store.add_audit_event(
        'auth.logout',
        actor=current_user,
        remote_address=request.remote_addr,
    )
    logout_user()
    flash('You have been signed out.', 'success')
    return redirect(url_for('auth.login'))


@auth_bp.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        replacement = request.form.get('password', '')
        if not current_app.auth_store.verify_user(current_user.username, current_password):
            flash('Current password is incorrect.', 'error')
        elif replacement != request.form.get('password_confirm', ''):
            flash('New passwords do not match.', 'error')
        else:
            try:
                current_app.auth_store.set_password(current_user.id, replacement)
            except ValueError as error:
                flash(str(error), 'error')
            else:
                current_app.auth_store.add_audit_event(
                    'account.password_changed',
                    actor=current_user,
                    target=current_user.username,
                    remote_address=request.remote_addr,
                )
                refreshed_user = current_app.auth_store.get_user(current_user.id)
                login_user(refreshed_user)
                flash('Password changed.', 'success')
                return redirect(url_for('auth.account'))
    return render_template('auth/account.html')


@auth_bp.route('/users', methods=['GET', 'POST'])
@admin_required
def users():
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password != request.form.get('password_confirm', ''):
            flash('Passwords do not match.', 'error')
        else:
            try:
                user = current_app.auth_store.create_user(
                    request.form.get('username', ''),
                    password,
                    request.form.get('display_name', ''),
                    request.form.get('role', 'viewer'),
                )
            except ValueError as error:
                flash(str(error), 'error')
            else:
                current_app.auth_store.add_audit_event(
                    'account.created',
                    actor=current_user,
                    target=user.username,
                    details={'role': user.role},
                    remote_address=request.remote_addr,
                )
                flash(f'Created {user.username}.', 'success')
                return redirect(url_for('auth.users'))

    return render_template(
        'auth/users.html',
        users=current_app.auth_store.list_users(),
        audit_events=current_app.auth_store.list_audit_events(50),
    )


@auth_bp.post('/users/<user_id>/toggle')
@admin_required
def toggle_user(user_id):
    user = current_app.auth_store.get_user(user_id)
    if not user:
        abort(404)
    if user.id == current_user.id:
        flash('You cannot disable your own account.', 'error')
    elif user.is_admin and user.active and current_app.auth_store.count_active_admins() <= 1:
        flash('At least one active administrator is required.', 'error')
    else:
        current_app.auth_store.set_active(user.id, not user.active)
        action = 'enabled' if not user.active else 'disabled'
        current_app.auth_store.add_audit_event(
            f'account.{action}',
            actor=current_user,
            target=user.username,
            remote_address=request.remote_addr,
        )
        flash(f'{user.username} {action}.', 'success')
    return redirect(url_for('auth.users'))


@auth_bp.post('/users/<user_id>/reset-password')
@admin_required
def reset_user_password(user_id):
    user = current_app.auth_store.get_user(user_id)
    if not user:
        abort(404)
    password = request.form.get('password', '')
    if password != request.form.get('password_confirm', ''):
        flash('Passwords do not match.', 'error')
    else:
        try:
            current_app.auth_store.set_password(user.id, password)
        except ValueError as error:
            flash(str(error), 'error')
        else:
            current_app.auth_store.add_audit_event(
                'account.password_reset',
                actor=current_user,
                target=user.username,
                remote_address=request.remote_addr,
            )
            flash(f'Reset the password for {user.username}.', 'success')
    return redirect(url_for('auth.users'))
