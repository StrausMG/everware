from os.path import join as pjoin
from tempfile import TemporaryDirectory

import docker
from docker.errors import DockerException
from traitlets import Int
from tornado import gen

from .spawner import CustomDockerSpawner


__all__ = ['TLS_FILES', 'ByorDockerSpawner']


TLS_FILES = ('cert.pem', 'key.pem', 'ca.pem')


def _make_empty_byor_config():
    config = {
        'client': None,
        'ip': None,
        'port': None,
        'tls_dir': None
    }
    return config


class ByorDockerSpawner(CustomDockerSpawner):
    """The class implements the concept \"Bring Your Own Resources\".

    It allows to accept optional information about the server where the user wants to
    run all the stuff. Namely, information includes the IP-address and the port of a Docker-daemon.
    The scenario where the daemon is protected via TLS is supported as well.
    """
    byor_timeout = Int(20, min=1, config=True,
                       help='Timeout for connection to BYOR Docker daemon')

    def __init__(self, **kwargs):
        CustomDockerSpawner.__init__(self, **kwargs)
        self._byor_config = _make_empty_byor_config()
        if self.options_form == self._options_form_default():
            with open(pjoin(self.config['JupyterHub']['template_paths'][0],
                            '_byor_options_form.html')) as form:
                ByorDockerSpawner.options_form = form.read()

    @property
    def client(self):
        byor_client = self._byor_config['client']
        if byor_client is not None:
            return byor_client
        return super(ByorDockerSpawner, self).client

    @property
    def byor_is_used(self):
        return self.user_options.get('byor_is_needed', False)

    def _reset_byor(self):
        self.container_ip = str(self.__class__.container_ip)
        self._byor_config = _make_empty_byor_config()

    def _prepare_tls_dir(self, content):
        """Make a temporary directory containing the user's credentials.

        Parameters
        ----------
        content : dict
            Must contain keys "cert.pem", "key.pem" and "ca.pem"
            mapped to contents of the corresponding files.
            (May contain anything else)
        """
        tls_dir = TemporaryDirectory(prefix='everware')
        missing_tls_files = []
        for filename in TLS_FILES:
            with open(pjoin(tls_dir.name, filename), 'w') as tls_file:
                try:
                    tls_file.write(content[filename])
                except KeyError:
                    missing_tls_files.append(filename)
        if missing_tls_files:
            message = 'Some files necessary for TLS are missing: {}'.format(
                missing_tls_files
            )
            self._add_to_log(message, level=2)
            raise ValueError(message)
        return tls_dir

    def options_from_form(self, formdata):
        options = {}
        options['byor_is_needed'] = formdata.pop('byor_is_needed', ['off'])[0].strip() == 'on'
        if options['byor_is_needed']:
            options['byor_settings'] = byor_settings = {}
            for field in ('ip', 'port'):
                byor_settings[field] = formdata.pop('byor_docker_' + field, None)[0].strip()
            byor_credentials = formdata.pop('byor_credentials__file', None)
            if byor_credentials is not None:
                byor_files = {x['filename']: x['body'].decode('utf-8') for x in byor_credentials}
                byor_settings['tls_dir'] = self._prepare_tls_dir(byor_files)
        options.update(
            super(ByorDockerSpawner, self).options_from_form(formdata)
        )
        return options

    def _make_byor_docker_client(self):
        tls_dir = self._byor_config['tls_dir']
        if tls_dir is not None:
            tls_config = docker.tls.TLSConfig(
                client_cert=(pjoin(tls_dir.name, 'cert.pem'), pjoin(tls_dir.name, 'key.pem')),
                ca_cert=pjoin(tls_dir.name, 'ca.pem'),
                verify=True
            )
        else:
            tls_config = None
        # version='auto' causes a connection to the daemon.
        # That's why the method must be a coroutine.
        client = docker.Client(
            '{}:{}'.format(self._byor_config['ip'], self._byor_config['port']),
            version='auto',
            timeout=self.byor_timeout,
            tls=tls_config
        )
        return client

    @gen.coroutine
    def _async_make_byor_docker_client(self):
        return self._make_byor_docker_client()

    @gen.coroutine
    def _configure_byor(self):
        """Configure BYOR settings or reset them if BYOR is not needed."""
        if not self.byor_is_used:
            self._reset_byor()
            return

        byor_config = self._byor_config
        byor_config.update(self.user_options['byor_settings'])
        self.container_ip = byor_config['ip']

        try:
            byor_config['client'] = yield self._async_make_byor_docker_client()
        except DockerException as e:
            self._is_failed = True
            message = str(e)
            if 'ConnectTimeoutError' in message:
                log_message = 'Connection to the Docker daemon took too long (> {} secs)'.format(
                    self.byor_timeout
                )
                notification_message = 'BYOR timeout limit {} exceeded'.format(
                    self.byor_timeout
                )
            else:
                log_message = "Failed to establish connection with the Docker daemon. Reason: {}".format(
                    message
                )
                notification_message = log_message
            self._add_to_log(log_message, level=2)
            yield self.notify_about_fail(notification_message)
            self._is_building = False
            raise

    @gen.coroutine
    def _prepare_for_start(self):
        super(ByorDockerSpawner, self)._prepare_for_start()
        yield self._configure_byor()

    @gen.coroutine
    def start(self, image=None):
        yield self._prepare_for_start()
        ip_port = yield self._start(image)
        return ip_port

    def clear_state(self):
        self._reset_byor()
        super(ByorDockerSpawner, self).clear_state()

    def get_state(self):
        state = super(ByorDockerSpawner, self).get_state()
        if not self.byor_is_used:
            return state
        byor_config = self._byor_config
        byor_state = {
            'ip': byor_config['ip'],
            'port': byor_config['port']
        }
        tls_dir = byor_config['tls_dir']
        byor_state['tld_is_used'] = tls_dir is not None
        if byor_state['tld_is_used']:
            for filename in TLS_FILES:
                with open(pjoin(tls_dir.name, filename), encoding='utf-8') as tls_file:
                    byor_state[filename] = tls_file.read()
        state['byor'] = byor_state
        return state

    def load_state(self, state):
        self._byor_config = _make_empty_byor_config()
        byor_state = state.get('byor')
        if byor_state is not None:
            byor_config = self._byor_config
            byor_config['ip'] = byor_state['ip']
            byor_config['port'] = byor_state['port']
            if byor_state['tld_is_used']:
                byor_config['tls_dir'] = self._prepare_tls_dir(byor_state)
            try:
                byor_config['client'] = self._make_byor_docker_client()
                self.container_ip = byor_state['ip']
            except Exception as error:
                message = 'Failed to create a docker client for user {}. Reason: {}'.format(
                    self.user.name, str(error)
                )
                self._add_to_log(message, level=1)
                self._reset_byor()
        super(ByorDockerSpawner, self).load_state(state)
