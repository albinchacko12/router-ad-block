import logging
import signal
import threading

from .config import Config
from .dns_server import start_dns
from .filter import Filter
from .web import start_web


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = Config.from_env()
    filter_ = Filter(config.data_dir, config.list_refresh_hours)
    filter_.start_refresher()
    start_dns(filter_, config)
    start_web(filter_, config)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        stop.wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
