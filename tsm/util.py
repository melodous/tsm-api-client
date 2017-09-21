import datetime
import functools
import logging

__author__ = 'Björn Braunschweig <bbrauns@gwdg.de>'


def log_execution_time(func):
    """
    Decorator that logs the function call and elapsed time.
    :param func:
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        start = datetime.datetime.now()
        logging.info('begin: {0}'.format(func.__name__))
        result = func(*args, **kwargs)
        end = datetime.datetime.now()
        logging.info('end: {0}, elapsed: {1}'.format(func.__name__, end - start))
        return result
    return wrapper


def format_bytes_human_readable(nbytes):
    suffixes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    nbytes = float(nbytes)
    if nbytes == 0:
        return '0 B'
    i = 0
    while nbytes >= 1024.0 and i < len(suffixes) - 1:
        nbytes /= 1024.0
        i += 1
    f = ('%.2f' % nbytes).rstrip('0').rstrip('.')
    return '{0} {1}'.format(f, suffixes[i])


def calculate_rate_human_readable(size_bytes, elaped_seconds):
    assert elaped_seconds is not None

    if elaped_seconds > 0:
        return format_bytes_human_readable(size_bytes / elaped_seconds)
    else:
        logging.info('can not calculate rate. elapsed_seconds is 0')
        return 'unknown'
