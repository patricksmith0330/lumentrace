from django.conf import settings
from django.db import models


class AuditEvent(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name='lumentrace_audit_events',
    )
    actor_username = models.CharField(max_length=150, blank=True)
    event_type = models.CharField(max_length=100)
    target = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict, blank=True)
    remote_address = models.GenericIPAddressField(null=True, blank=True)

    class Meta:
        ordering = ['-id']

    @property
    def event_label(self):
        return self.event_type.replace('.', ' ').title()
