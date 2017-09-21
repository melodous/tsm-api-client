import tsm.rc_codes as tsm_rc_codes
from tsm.definitions import *

__author__ = 'Björn Braunschweig <bbrauns@gwdg.de>'


def translate_rc_to_mnemonic(rc):
    if isinstance(rc, c_short):
        rc = rc.value
    if isinstance(rc, c_int):
        rc = rc.value
    if isinstance(rc, c_ushort):
        rc = rc.value
    if rc is None:
        return 'unknown'
    module_vars = dir(tsm_rc_codes)
    dsm_vars = filter(lambda x: x.startswith('DSM'), module_vars)
    for dsm_var in dsm_vars:
        k = getattr(tsm_rc_codes, dsm_var)
        if k == rc:
            return dsm_var
    return 'unknown'


def str_to_bytes(val):
    return val.encode('ascii')


def bytes_to_str(val):
    return val.decode('ascii')


def convert_size_to_hi_lo(size):
    bin_str = '{0:064b}'.format(size)
    hi = int(bin_str[:32], 2)
    lo = int(bin_str[32:], 2)
    return hi, lo


def convert_hi_lo_to_size(hi, lo):
    bin_high = '{0:032b}'.format(hi)
    bin_low = '{0:032b}'.format(lo)
    bin_str = bin_high + bin_low
    return int(bin_str, 2)


def media_class_to_str(media_class):
    media_classes = {str(MEDIA_FIXED): 'fixed',
                     str(MEDIA_LIBRARY): 'library',
                     str(MEDIA_NETWORK): 'network',
                     str(MEDIA_SHELF): 'shelf',
                     str(MEDIA_OFFSITE): 'offsite',
                     str(MEDIA_UNAVAILABLE): 'unavailable'}
    return media_classes.get(str(media_class), 'unknown')


# noinspection PyProtectedMember,PyTypeChecker
def convert_tsm_structure_to_str(struct, depth=0):
    repr_str = ''
    for field_definition in struct._fields_:
        value = getattr(struct, field_definition[0])
        if value is dsStruct64_t:
            value = str(convert_hi_lo_to_size(hi=value.hi,
                                              lo=value.lo))
        elif isinstance(value, Structure):
            value = '{\n' + convert_tsm_structure_to_str(value, depth + 1) + '}'  # recursive
        else:
            value = getattr(struct, field_definition[0])
        repr_str += " " * depth + '{field}={value}, \n'.format(field=field_definition[0], value=value)
    return repr_str
