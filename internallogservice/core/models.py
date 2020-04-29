from django.db import models

# Create your models here.


class EmailAlerts(models.Model):
    email = models.EmailField(max_length=254)
    send_log = models.CharField(max_length=100)
    day_of_week = models.CharField(max_length=100)
    time = models.TimeField()
    file_format = models.CharField(max_length=100)
    include_all = models.BooleanField()
    log_type = models.CharField(max_length=100)
    created_date = models.DateTimeField(null=True, blank=True)
    sent_date = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.email


class DomainFields(models.Model):
    email_alerts = models.ForeignKey(EmailAlerts, on_delete=models.CASCADE)
    domain = models.CharField(max_length=254)
    proto = models.CharField(max_length=254)
    source = models.GenericIPAddressField()
    destination = models.GenericIPAddressField()
    action = models.CharField(max_length=100)
    reason = models.TextField(blank=True)
    device = models.TextField(blank=True)


class PacketFields(models.Model):
    email_alerts = models.ForeignKey(EmailAlerts, on_delete=models.CASCADE)
    country = models.CharField(max_length=254)
    asName = models.CharField(max_length=254)
    proto = models.CharField(max_length=254)
    source = models.GenericIPAddressField()
    destination = models.GenericIPAddressField()
    direction = models.CharField(max_length=254)
    action = models.CharField(max_length=254)
    category = models.CharField(max_length=254)
    reason = models.TextField(blank=True)
    list = models.CharField(max_length=254)
    group = models.CharField(max_length=254)
    device = models.TextField(blank=True)