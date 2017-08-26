from os.path import join as pjoin
from tempfile import NamedTemporaryFile

import docker
from docker.errors import DockerException
from traitlets import Int
from tornado import gen

from .spawner import CustomDockerSpawner


class ByorDockerSpawner(CustomDockerSpawner):
    byor_timeout = Int(20, min=1, config=True,
                       help='Timeout for connection to BYOR Docker daemon').default_value

    BYOR_OFF = 'off'  # byor was not requested by user
    BYOR_ON = 'on'  # byor was requested by user and is ready to use
    BYOR_NOT_READY = 'not_ready'  # byor was requested by user and is being prepared
    BYOR_NOT_VALID = 'not_valid'  # byor was requested by user, but something went wrong
    byor_statuses = [BYOR_OFF, BYOR_ON, BYOR_NOT_READY, BYOR_NOT_VALID]

    def __init__(self, **kwargs):
        CustomDockerSpawner.__init__(self, **kwargs)
        self._byor_config = self.make_empty_byor_config()
        if self.options_form == self._options_form_default():
            with open(pjoin(self.config['JupyterHub']['template_paths'][0],
                            '_byor_options_form.html')) as form:
                ByorDockerSpawner.options_form = form.read()

    @staticmethod
    def make_empty_byor_config():
        config = {
            'status': 'off',
            'client': None,
            'ip': None,
            'port': None,
            'tls': None,
            'cert': None,
            'key': None,
            'ca': None
        }
        return config

    @property
    def client(self):
        byor_client = self._byor_config['client']
        if byor_client is not None:
            return byor_client
        return super(ByorDockerSpawner, self).client

    @property
    def byor_is_used(self):
        return self.user_options.get('byor_is_needed', False)

    @property
    def byor_status(self):
        return self._byor_config['status']

    def _set_byor_status(self, status):
        if status not in ByorDockerSpawner.byor_statuses:
            message = 'value must be one of [{}]'.format(', '.join(ByorDockerSpawner.byor_status))
            raise ValueError(message)
        self._byor_config['status'] = status

    def _reset_byor(self):
        self.container_ip = str(self.__class__.container_ip)
        self._byor_config = self.make_empty_byor_config()

    def options_from_form(self, formdata):
        options = {}
        options['byor_is_needed'] = formdata.pop('byor_is_needed', [''])[0].strip() == 'on'
        if options['byor_is_needed']:
            options['byor_settings'] = byor_settings = {}
            for field in ('ip', 'port'):
                byor_settings[field] = formdata.pop('byor_docker_' + field, None)[0].strip()
            byor_credentials = formdata.pop('byor_credentials__file', [''])
            if byor_credentials != ['']:
                byor_files = {x['filename']: x['body'] for x in byor_credentials}
                missing_tls_files = []
                for filename in ('cert.pem', 'key.pem', 'ca.pem'):
                    temporary_file = NamedTemporaryFile(suffix='-everware')
                    try:
                        temporary_file.write(byor_files[filename])
                    except KeyError:
                        missing_tls_files.append(filename)
                    byor_settings[filename[:-len('.pem')]] = temporary_file
                print('DDD', missing_tls_files)
                if missing_tls_files:
                    message = 'Some files necessary for TLS are missing: {}'.format(
                        missing_tls_files
                    )
                    self._add_to_log(message, level=2)
                    raise ValueError(message)
        options.update(
            super(ByorDockerSpawner, self).options_from_form(formdata)
        )
        return options

    @gen.coroutine
    def _configure_byor(self):
        """Configure BYOR settings or reset them if BYOR is not needed."""
        if not self.byor_is_used:
            self._reset_byor()
            return
        self._set_byor_status(ByorDockerSpawner.BYOR_NOT_READY)
        byor_config = self._byor_config
        byor_config.update(self.user_options['byor_settings'])
        self.container_ip = byor_config['ip']
        if byor_config['cert'] is not None:
            byor_config['tls'] = docker.tls.TLSConfig(
                client_cert=(byor_config['cert'].name, byor_config['key'].name),
                ca_cert=byor_config['ca'].name,
                verify=True
            )
        try:
            # version='auto' causes a connection to the daemon.
            # That's why the method must be a coroutine.
            byor_config['client'] = docker.Client(
                '{}:{}'.format(byor_config['ip'], byor_config['port']),
                version='auto',
                timeout=ByorDockerSpawner.byor_timeout,
                tls=byor_config['tls']
            )
        except DockerException as e:
            print(e)
            self._is_failed = True
            message = str(e)
            if 'ConnectTimeoutError' in message:
                log_message = 'Connection to the Docker daemon took too long (> {} secs)'.format(
                    ByorDockerSpawner.byor_timeout
                )
                notification_message = 'BYOR timeout limit {} exceeded'.format(
                    ByorDockerSpawner.byor_timeout
                )
            else:
                log_message = "Failed to establish connection with the Docker daemon"
                notification_message = log_message
            self._add_to_log(log_message, level=2)
            yield self.notify_about_fail(notification_message)
            self._is_building = False
            self._set_byor_status(ByorDockerSpawner.BYOR_NOT_VALID)
            raise
        else:
            self._set_byor_status(ByorDockerSpawner.BYOR_ON)

    @gen.coroutine
    def _prepare_for_start(self):
        super(ByorDockerSpawner, self)._prepare_for_start()
        yield self._configure_byor()

    @gen.coroutine
    def start(self, image=None):
        yield self._prepare_for_start()
        ip_port = yield self._start(image)
        return ip_port
