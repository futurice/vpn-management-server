from django.db import models
import datetime

class State(models.Model):
    username = models.CharField(max_length=60, primary_key=True)
    valid_csr = models.BooleanField(default=False)
    password = models.CharField(max_length=20, blank=True, null=True)
    csr_filename = models.CharField(max_length=255, blank=True, null=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    cn = models.CharField(max_length=255, blank=True, null=True)

    def expired(self):
        age = (datetime.datetime.now() - self.timestamp).seconds
        if age > 900:
            return True
        return False

    
