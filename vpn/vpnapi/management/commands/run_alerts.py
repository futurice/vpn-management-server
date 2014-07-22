from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from vpncert import alert

class Command(BaseCommand):
	can_import_settings = True

	def handle(self, *args, **kwargs):
		a = alert()
		a.run()
		self.stdout.write('Successfully ran alerts')