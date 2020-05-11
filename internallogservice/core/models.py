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
        return self.email, self.send_log, self.day_of_week, self.time, self.file_format, self.include_all, \
               self.log_type, self.created_date, self.sent_date, self.packet_country, self.packet_asName, \
               self.packet_proto, self.packet_source, self.packet_destination, self.packet_direction, \
               self.packet_action, self.packet_category, self.packet_reason, self.packet_list, self.packet_group, \
               self.packet_device


# class DomainFields(models.Model):
#     email_alerts = models.ForeignKey(EmailAlerts, on_delete=models.CASCADE)
#     domain = models.CharField(max_length=254)
#     proto = models.CharField(max_length=254)
#     source = models.GenericIPAddressField()
#     destination = models.GenericIPAddressField()
#     action = models.CharField(max_length=100)
#     reason = models.TextField(blank=True)
#     device = models.TextField(blank=True)
#
#     def __str__(self):
#         return self.domain, self.proto, self.source, self.destination, self.action, self.reason, self.device
#
#
# class PacketFields(models.Model):
#     email_alerts = models.ForeignKey(EmailAlerts, on_delete=models.CASCADE)
#     country = models.CharField(max_length=254)
#     asName = models.CharField(max_length=254)
#     proto = models.CharField(max_length=254)
#     source = models.GenericIPAddressField()
#     destination = models.GenericIPAddressField()
#     direction = models.CharField(max_length=254)
#     action = models.CharField(max_length=254)
#     category = models.CharField(max_length=254)
#     reason = models.TextField(blank=True)
#     list = models.CharField(max_length=254)
#     group = models.CharField(max_length=254)
#     device = models.TextField(blank=True)
#
#     def __str__(self):
#         return self.country, self.asName, self.proto, self.source, self.destination, \
#                self.direction, self.action, self.category, self.reason, self.list, self.group, self.device
