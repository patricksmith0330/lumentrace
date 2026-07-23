from django.contrib.auth.hashers import BasePasswordHasher, mask_hash
from django.utils.translation import gettext_noop as _
from werkzeug.security import check_password_hash


class WerkzeugScryptPasswordHasher(BasePasswordHasher):
    """Verify v3 Flask hashes once, then let Django upgrade them on login."""

    algorithm = 'scrypt:32768:8:1'

    def encode(self, password, salt):
        raise NotImplementedError('Legacy hashes are verification-only.')

    def verify(self, password, encoded):
        try:
            return check_password_hash(encoded, password)
        except (TypeError, ValueError):
            return False

    def safe_summary(self, encoded):
        algorithm, _separator, remainder = encoded.partition('$')
        salt, _separator, digest = remainder.partition('$')
        return {
            _('algorithm'): algorithm,
            _('salt'): mask_hash(salt),
            _('hash'): mask_hash(digest),
        }

    def must_update(self, encoded):
        return True

    def harden_runtime(self, password, encoded):
        return None
