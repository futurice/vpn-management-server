from django.db import models

class Log(models.Model):
    hash = models.CharField(max_length=41,unique=True)

    server_name = models.CharField(max_length=50)
    endpoint_location = models.CharField(max_length=50)
    general = models.BooleanField(default=False)
    
    username = models.CharField(max_length=50,null=True,blank=True)
    timestamp = models.DateTimeField()
    message = models.CharField(max_length=1500)

    def __unicode__(self):
        return self.message

class Connections(models.Model):
    server_name = models.CharField(max_length=50)
    endpoint_location = models.CharField(max_length=50)
    common_name = models.CharField(max_length=50)
    username = models.CharField(max_length=50)

    opened_at = models.DateTimeField()
    closed_at = models.DateTimeField(null=True)    
    remote_ip = models.IPAddressField()
    virtual_address = models.IPAddressField()
    bytes_received = models.BigIntegerField()
    bytes_sent = models.BigIntegerField()

    def __unicode__(self):
        return self.server_name, common_name, opened_at, closed_at
