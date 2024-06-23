from django.core.management.commands.runserver import Command as RunserverCommand
import subprocess

class Command(RunserverCommand):
    def handle(self, *args, **options):
        addrport = options['addrport']
        if addrport is None:
            addrport = '127.0.0.1:8000'  # Default address and port

        # Split the address and port if provided
        if ':' in addrport:
            addr, port = addrport.split(':')
        else:
            addr = addrport
            port = '8000'

        # Prepare the argument list for Daphne
        daphne_args = [
            'daphne',
            # '-u',  # Necessary for Unix sockets
            '--bind', addr,
            '--port', port,
            '_site.asgi:application'
        ]

        # Execute Daphne with the prepared arguments
        try:
            subprocess.run(daphne_args, check=True)
        except subprocess.CalledProcessError as e:
            self.stderr.write(f'Error running Daphne: {e}')
