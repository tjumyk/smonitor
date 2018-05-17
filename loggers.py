import logging

logging.basicConfig(format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', level=logging.INFO)
muted_loggers = ['engineio', 'socketio', 'geventwebsocket.handler']
for _name in muted_loggers:
    logging.getLogger(_name).setLevel(logging.WARNING)


def get_logger(name: str = None) -> logging.Logger:
    return logging.getLogger(name)
