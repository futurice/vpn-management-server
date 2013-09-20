from django.contrib.auth.models import User
from django.db import models

from django.conf import settings

class Employment(models.Model):
    name = models.CharField(max_length=50)
    descr = models.CharField(max_length=100)
    def __unicode__(self):
        return self.descr

class Computertype(models.Model):
    name = models.CharField(max_length=50)
    descr = models.CharField(max_length=100)
    def __unicode__(self):
        return self.descr

class Computerowner(models.Model):
    name = models.CharField(max_length=50)
    descr = models.CharField(max_length=100)
    def __unicode__(self):
        return self.descr

class HelpChoices(models.Model):
    name = models.CharField(max_length=50)
    descr = models.CharField(max_length=100)
    def __unicode__(self):
        return self.descr

class Log(models.Model):
    cn = models.CharField(max_length=50)
    timestamp = models.DateTimeField()
    message = models.CharField(max_length=250)
