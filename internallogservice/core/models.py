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
    remarks = models.TextField(null=True, blank=True)
    domain_domain = models.CharField(max_length=254, null=True, blank=True)
    domain_proto = models.CharField(max_length=254, null=True, blank=True)
    domain_source = models.GenericIPAddressField(null=True, blank=True)
    domain_destination = models.GenericIPAddressField(null=True, blank=True)
    domain_action = models.CharField(max_length=100, null=True, blank=True)
    domain_reason = models.TextField(null=True, blank=True)
    domain_device = models.TextField(null=True, blank=True)
    packet_country = models.CharField(max_length=254, null=True, blank=True)
    packet_asName = models.CharField(max_length=254, null=True, blank=True)
    packet_proto = models.CharField(max_length=254, null=True, blank=True)
    packet_source = models.GenericIPAddressField(null=True, blank=True)
    packet_destination = models.GenericIPAddressField(null=True, blank=True)
    packet_direction = models.CharField(max_length=254, null=True, blank=True)
    packet_action = models.CharField(max_length=254, null=True, blank=True)
    packet_category = models.CharField(max_length=254, null=True, blank=True)
    packet_reason = models.TextField(null=True, blank=True)
    packet_list = models.CharField(max_length=254, null=True, blank=True)
    packet_group = models.CharField(max_length=254, null=True, blank=True)
    packet_device = models.TextField(null=True, blank=True)

    def __str__(self):
        template = '{0.email} {0.send_log} {0.day_of_week} {0.time} {0.file_format} {0.include_all} \
                {0.log_type} {0.created_date} {0.sent_date} {0.remarks} {0.packet_country} {0.packet_asName} \
                {0.packet_proto} {0.packet_source} {0.packet_destination} {0.packet_direction} \
                {0.packet_action} {0.packet_category} {0.packet_reason} {0.packet_list} {0.packet_group} \
                {0.packet_device} {0.domain_domain} {0.domain_proto} {0.domain_source} {0.domain_destination}  \
                {0.domain_action} {0.domain_reason} {0.domain_device}'
        return template.format(self)

    class Meta:
        verbose_name_plural = 'EmailAlerts'


class GMCApiKey(models.Model):
    api_key = models.TextField(null=True, blank=True)

    def __str__(self):
        return self.api_key


