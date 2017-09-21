import collections
import ctypes
import datetime
import logging
import os
from operator import attrgetter
from typing import List

from tsm.rc_codes import *
from tsm.definitions import *
from tsm.util import log_execution_time, calculate_rate_human_readable
from tsm.helper import convert_size_to_hi_lo, convert_hi_lo_to_size, convert_tsm_structure_to_str, \
    str_to_bytes, translate_rc_to_mnemonic, bytes_to_str
from tsm.method_proxy import TSMApiMethodProxy

__author__ = 'Björn Braunschweig <bbrauns@gwdg.de>'

logger = logging.getLogger(__name__)

query_result_tuple = collections.namedtuple('query_result_tuple', 'obj_id size_estimate ins_date fs hl ll')
tsm_path_tuple = collections.namedtuple('tsm_path', 'fs hl ll')


class TSMError(Exception):
    def __init__(self, msg, rc):
        self.rc = rc
        super(TSMError, self).__init__(msg)


class TSMNotFoundError(TSMError):
    def __init__(self, msg):
        super(TSMNotFoundError, self).__init__(msg, rc=None)


class TSMApiClient(object):
    """
    A TSMApiClient instance is capable to archive and retrieve arbitrary sized files
    in combination with a TSM Server.

    More information regarding the TSM Api:
    http://publib.boulder.ibm.com/tividd/td/TSMC/GC32-0793-02/en_US/HTML/ansa000064.htm
    """

    def __init__(self):
        self.dsm_handle = None
        self.send_buffer_len = 1024 * 1024  # 1 MB
        self.receive_buffer_len = 1024 * 1024  # 1 MB
        self.filespace_type = 'UNIX'
        self.filespace_info = 'test-api'
        self.method_proxy = TSMApiMethodProxy()

    def connect(self):
        if not self.dsm_handle:
            logger.info('establishing connection to tsm server.')
            self._check_api_version()
            self.dsm_handle = self._init_session()
            logger.info('using handle: {0}'.format(self.dsm_handle.value))
            info = self.query_session_info()
            logger.info('session info:')
            info_str = convert_tsm_structure_to_str(info)
            logger.info(info_str)
        else:
            logger.info('using session with handle: {0}'.format(self.dsm_handle.value))
            try:
                # check if session is still valid
                self.query_session_info()
            except TSMError as _err:
                if _err.rc == DSM_RC_INVALID_DS_HANDLE:
                    logger.info('DSM_RC_INVALID_DS_HANDLE occurred. refreshing handle...')
                    self.dsm_handle = None
                    self.connect()
                else:
                    raise

    def close(self):
        if self.dsm_handle:
            logger.info('terminating handle')
            self.method_proxy.dsmTerminate(self.dsm_handle)

    def _raise_err(self, rc):
        if self.dsm_handle:
            msg = ctypes.create_string_buffer(128)
            self.method_proxy.dsmRCMsg(self.dsm_handle, rc, msg)
            raise TSMError(msg.value, rc)
        else:
            mnemonic = translate_rc_to_mnemonic(rc)
            raise TSMError('unknown error, rc={0}, mnemonic={1}'.format(rc, mnemonic), rc)

    def _raise_err_on_rc(self, rc):
        if rc != DSM_RC_OK:
            self._raise_err(rc)

    def log_dsm_rc_msg(self):
        def err_check(rc, func, funcargs):
            logger.info('dsm func call: {0}, rc={1}'.format(func.__name__, rc))
            if self.dsm_handle is not None and rc != DSM_RC_OK:
                msg = ctypes.create_string_buffer(128)
                self.method_proxy.dsmRCMsg(self.dsm_handle, rc, msg)
                logger.info('dsm API msg: {0}'.format(msg.value))
            return rc

        return err_check

    @staticmethod
    def _normalize_input(filename, filespace, highlevel, lowlevel):
        if lowlevel is None:
            lowlevel = '/' + os.path.basename(filename)
        if not lowlevel.startswith('/'):
            lowlevel = '/' + lowlevel
        if not highlevel.startswith('/'):
            highlevel = '/' + highlevel
        if not filespace.startswith('/'):
            filespace = '/' + filespace
        return filespace, highlevel, lowlevel

    @log_execution_time
    def archive(self, filename, filespace, highlevel, lowlevel=None):
        """
        Archive a file to TSM.
        :param filename: source file
        :param filespace: TSM filespace
        :param highlevel: TSM highlevel name
        :param lowlevel: TSM lowlevel name
        :return:
        """
        assert filename
        assert os.path.exists(filename)
        assert filespace
        assert highlevel

        self.connect()

        fs, hl, ll = self._normalize_input(filename, filespace, highlevel, lowlevel)
        self._register_fs(fs, self.filespace_type, self.filespace_info)
        self._begin_tx()
        logger.info('starting to archive filename={0} to filespace={1}, highlevel={2}, lowlevel={3}'.format(
            filename, fs, hl, ll))
        dsm_obj_name = self._bind_mc(fs, hl, ll)
        self._send_obj(dsm_obj_name, filename)
        self._send_data(filename)
        self._end_send_obj()
        self._end_tx()

    def query(self, filespace, highlevel, lowlevel) -> List[query_result_tuple]:
        """
        Queries objects sorted by newest date first. Returns empty list on
        nothing found.
        """
        assert filespace
        assert highlevel
        assert lowlevel

        self.connect()

        fs, hl, ll = self._normalize_input(None, filespace, highlevel, lowlevel)
        self._begin_query(fs, hl, ll)
        found_objs = self._get_next_query_obj()
        self._end_query()
        return found_objs

    @log_execution_time
    def retrieve(self, dest_file, filespace, highlevel, lowlevel=None):
        """
        Retrieves an archived file.
        :param dest_file: destination file
        :param filespace: TSM filespace
        :param highlevel: TSM highlevel name
        :param lowlevel: TSM lowlevel name. If lowlevel name is None
        the basename of dest_file is used.
        :return:
        """
        assert dest_file
        assert filespace
        assert highlevel

        self.connect()

        fs, hl, ll = self._normalize_input(dest_file, filespace, highlevel, lowlevel)
        found_objs = self.query(fs, hl, ll)

        count = len(found_objs)
        if count == 0:
            raise TSMNotFoundError('object can not be found.'
                                   ' filespace:{0}, highlevel:{1}, lowlevel:{2}'.format(fs,
                                                                                        hl,
                                                                                        ll))
        else:
            # in case of migrations
            if count > 1:
                logging.info('found {} objects. using latest.'.format(count))
            self._begin_get_data(found_objs[0].obj_id)
            data_blk, buff, rc = self._get_obj(found_objs[0].obj_id)
            self._get_data(dest_file, data_blk, buff, found_objs[0].size_estimate, rc)
            self._end_get_obj()
            self._end_get_data()

    def retrieve_all(self, dest_folder, arr):
        """
        Retrieves multiple archived files. The files will be placed in
        dest_folder/<fs>/<hl>/<ll>.
        :param dest_folder: folder to save the retrieved files
        :param arr: files to retrieve
        :return:
        """
        assert dest_folder is not None
        assert arr

        self.connect()

        # query objs
        all_objs = []
        for a in arr:
            fs, hl, ll = self._normalize_input(None, a.fs, a.hl, a.ll)
            found_objs = self.query(fs, hl, ll)
            if not found_objs:
                raise TSMNotFoundError('object can not be found.'
                                       ' filespace:{0}, highlevel:{1}, lowlevel:{2}'.format(fs, hl, ll))
            all_objs = all_objs + found_objs  # concat lists
        # retrieve objs
        self._begin_get_data(list([x.obj_id for x in all_objs]))
        for o in all_objs:
            data_blk, buff, rc = self._get_obj(o.obj_id)
            dest_folder = dest_folder + o.fs + o.hl
            if not os.path.exists(dest_folder):
                os.makedirs(dest_folder)
            dest_filename = dest_folder + o.ll
            logger.info('saving file to: {}'.format(dest_filename))
            self._get_data(dest_filename, data_blk, buff, o.size_estimate, rc)
            self._end_get_obj()
        self._end_get_data()

    def delete(self, filespace, highlevel, lowlevel=None):
        """
        Delete an archived file.
        :param filespace: TSM filespace
        :param highlevel: TSM highlevel name
        :param lowlevel: TSM lowlevel name. If lowlevel name is None
        all objects under highlevel name are deleted.
        :return:
        """
        assert filespace is not None
        assert highlevel is not None

        self.connect()

        if lowlevel is None:
            lowlevel = '/*'
            logger.info('lowlevel not specified, setting lowlevel to: /*')
        fs, hl, ll = self._normalize_input(None, filespace, highlevel, lowlevel)
        found_objs = self.query(fs, hl, ll)
        if not found_objs:
            raise TSMNotFoundError('object can not be found.'
                                   ' filespace:{0}, highlevel:{1}, lowlevel:{2}'.format(fs,
                                                                                        hl,
                                                                                        ll))
        assert len(found_objs) < 5, 'sanity check for _delete_obj failed.'
        logger.info('found {0} objects.'.format(len(found_objs)))
        self._begin_tx()
        for obj in found_objs:
            self._delete_obj(obj.obj_id)
        self._end_tx()

    def log(self, msg: str, app_msg_id: str = '', app_name: str = '',
            severity: int = dsmLogSeverityEnum.logSevInfo,
            log_type: int = dsmLogTypeEnum.logServer):
        """
        The dsmLogEventEx function call logs a user message to the server log file, to the local error log,
        or to both. This call must be performed while at InSession state inside a session.
        Do not perform it within a send, get, or query. See Figure 20.
        The severity determines the Tivoli Storage Manager message number.
        To view messages that are logged on the server, use the query actlog command through the Administrative Client.
        Use the Tivoli Storage Manager client option, errorlogretention,
        to prune the client error log file if the application generates numerous client messages written to the client
        log (dsmLogType either logLocal or logBoth). Refer to the Tivoli Storage Manager Administrator's Reference for
        more information.
        :param msg: This parameter is the text of the event message to log. This must be a null-ended string.
        The maximum length is DSM_MAX_RC_MSG_LENGTH
        :param app_msg_id: This parameter is a string to identify the specific application message.
        The format we recommend is three characters that are followed by four numbers. For example DSM0250
        :param app_name:
        :param severity: This parameter is the event severity. The possible values are:
            logSevInfo,       /* information ANE4990 */
            logSevWarning,    /* warning     ANE4991 */
            logSevError,      /* Error       ANE4992 */
            logSevSevere      /* severe      ANE4993 */
        :param log_type: This parameter specifies where to direct the event.
            The possible values include: logServer, logLocal, or logBoth.
        :return:
        """
        assert msg is not None

        self.connect()

        dsm_log_ex_in = dsmLogExIn_t()
        dsm_log_ex_in.stVersion = dsmLogExInVersion
        dsm_log_ex_in.severity = severity
        dsm_log_ex_in.appMsgID = str_to_bytes(app_msg_id)
        dsm_log_ex_in.logType = log_type
        dsm_log_ex_in.appName = str_to_bytes(app_name)
        dsm_log_ex_in.message = str_to_bytes(msg)

        dsm_log_ex_out = dsmLogExOut_t()
        rc = self.method_proxy.dsmLogEventEx(self.dsm_handle, ctypes.byref(dsm_log_ex_in), ctypes.byref(dsm_log_ex_out))
        self._raise_err_on_rc(rc)

    def _delete_obj(self, obj_id):
        assert obj_id is not None

        del_info = dsmDelInfo()
        del_info.archInfo.stVersion = delArchVersion
        del_info.archInfo.objId = obj_id

        logger.info('deleting: objId.lo={0}, objId.hi={1}'.format(obj_id.lo, obj_id.hi))

        self.method_proxy.dsmDeleteObj.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmDeleteObj(self.dsm_handle, dsmDelTypeEnum.dtArchive, del_info)
        self._raise_err_on_rc(rc)

    def _check_api_version(self):
        """
        Check if this application client is compatible with the available api libraries.
        """
        apiversionex = dsmApiVersionEx()
        self.method_proxy.dsmQueryApiVersionEx(ctypes.byref(apiversionex))
        logger.info('API Version: {version}.{release}.{level}.{subLevel}'.format(
            version=apiversionex.version, release=apiversionex.release,
            level=apiversionex.level, subLevel=apiversionex.subLevel))
        applversion = (10000 * DSM_API_VERSION) + \
                      (1000 * DSM_API_RELEASE) + \
                      (100 * DSM_API_LEVEL) + DSM_API_SUBLEVEL
        apiversion = (10000 * apiversionex.version) + \
                     (1000 * apiversionex.release) + \
                     (100 * apiversionex.level) + apiversionex.subLevel

        # check for compatibility problems
        if apiversion < applversion:
            msg = 'The Tivoli Storage Manager API library Version = {0}.{1}.{2}.{3} is at a lower version\n'.format(
                apiversionex.version,
                apiversionex.release,
                apiversionex.level,
                apiversionex.subLevel)
            msg += ' than the application version = {0}.{1}.{2}.{3}\n'.format(
                DSM_API_VERSION,
                DSM_API_RELEASE,
                DSM_API_LEVEL,
                DSM_API_SUBLEVEL)
            msg += 'Please upgrade the API accordingly.'
            raise TSMError(msg, rc=None)

    @log_execution_time
    def _init_session(self):
        """
        Starts an API session using the additional parameters that permit extended verification.
        """
        api_appl_ver = dsmApiVersionEx()
        api_appl_ver.stVersion = apiVersionExVer
        api_appl_ver.version = DSM_API_VERSION
        api_appl_ver.release = DSM_API_RELEASE
        api_appl_ver.level = DSM_API_LEVEL
        api_appl_ver.subLevel = DSM_API_SUBLEVEL
        api_appl_ver_p = ctypes.pointer(api_appl_ver)

        app_ver = dsmAppVersion()
        app_ver.applicationVersion = DSM_API_VERSION
        app_ver.applicationRelease = DSM_API_RELEASE
        app_ver.applicationLevel = DSM_API_LEVEL
        app_ver.applicationSubLevel = DSM_API_SUBLEVEL

        init_in = dsmInitExIn_t()
        init_in.stVersion = dsmInitExInVersion
        init_in.apiVersionExP = api_appl_ver_p
        # Es wird die dsm.sys verwendet, gesetzt durch env variablen DSM_DIR usw.
        # initIn.clientNodeNameP     = ''
        # initIn.clientOwnerNameP    = ''
        # initIn.clientPasswordP     = ''
        init_in.applicationTypeP = str_to_bytes(self.filespace_type)
        # init_in.configfile = ''
        # initIn.options             = ''

        # initIn.userNameP           = ''
        # initIn.userPasswordP       = ''
        # initIn.dirDelimiter        = '\0'
        # initIn.useUnicode          = dsmFalse
        # initIn.bEncryptKeyEnabled  = dsmFalse
        # initIn.encryptionPasswordP = ''
        # initIn.appVersionP         = appVer

        initout = dsmInitExOut_t()
        initout.stVersion = dsmInitExOutVersion

        local_handle = dsUint32_t()
        self.method_proxy.dsmInitEx.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmInitEx(ctypes.byref(local_handle), ctypes.byref(init_in), ctypes.byref(initout))
        self._raise_err_on_rc(rc)
        logger.info('dsmInitEx')
        logger.info(
            'Connected to server: {server}, ver/rel/lev {ver}/{rel}/{lev}'.format(server=initout.adsmServerName,
                                                                                  ver=initout.serverVer,
                                                                                  rel=initout.serverRel,
                                                                                  lev=initout.serverLev))
        return local_handle

    @log_execution_time
    def query_session_info(self):
        """
        The dsmQuerySessInfo function call starts a query request to Tivoli Storage Manager for information
        related to the operation of the specified session in dsmHandle.
        A structure of type ApiSessInfo is passed in the call,
        with all available session related information entered.
        This call is started after a successful dsmInitEx call.
        """
        dsm_sess_info = ApiSessInfo()
        dsm_sess_info.stVersion = ApiSessInfoVersion
        self.method_proxy.dsmQuerySessInfo.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmQuerySessInfo(self.dsm_handle, ctypes.byref(dsm_sess_info))
        self._raise_err_on_rc(rc)
        return dsm_sess_info

    @log_execution_time
    def _register_fs(self, fs_name, fs_type, fs_info):
        """
        The dsmRegisterFS function call registers a new file space with the Tivoli Storage Manager server.
        Register a file space first before you can back up any data to it.
        :param fs_name: Filespace name to create
        :param fs_type: Filespace type: eg. UNIX
        :param fs_info: Descriptive info data
        """
        assert fs_name is not None
        assert fs_type is not None
        assert fs_info is not None
        dsm_reg_fs_data = regFSData()
        dsm_reg_fs_data.stVersion = regFSDataVersion
        dsm_reg_fs_data.fsName = str_to_bytes(fs_name)
        dsm_reg_fs_data.fsType = str_to_bytes(fs_type)
        dsm_reg_fs_data.fsAttr.unixFSAttr.fsInfo = str_to_bytes(fs_info)
        dsm_reg_fs_data.fsAttr.unixFSAttr.fsInfoLength = len(dsm_reg_fs_data.fsAttr.unixFSAttr.fsInfo)

        self.method_proxy.dsmRegisterFS.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmRegisterFS(self.dsm_handle, dsm_reg_fs_data)
        if rc == DSM_RC_FS_ALREADY_REGED:
            logger.info('filespace: {0} is already registered'.format(fs_name))
        else:
            self._raise_err_on_rc(rc)

    @log_execution_time
    def _begin_tx(self):
        """
        The dsmBeginTxn function call begins one or more Tivoli Storage Manager transactions
        that begin a complete action; either all the actions succeed or none succeed.
        An action can be either a single call or a series of calls. For example,
        a dsmSendObj call that is followed by a number of dsmSendData calls can be considered a single action.
        Similarly, a dsmSendObj call with a dataBlkPtr that indicates a data area containing the object
        to back up is also considered a single action.
        """
        self.method_proxy.dsmBeginTxn.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmBeginTxn(self.dsm_handle)
        self._raise_err_on_rc(rc)

    @log_execution_time
    def _bind_mc(self, filespace, highlevel, lowlevel):
        """
        The dsmBindMC function call associates, or binds, a management class to the passed object.
        The object is passed through the Include-Exclude list that is pointed to in the options file.
        If a match is not found in the Include list for a specific management class,
        the default management class is assigned.
        The Exclude list can prevent objects from a backup but not from an archive.
        :param filespace: The filespace name associated for this object
        :param highlevel: The highlevel name associated for this object
        :param lowlevel: The lowlevel name associated for this object
        """
        assert filespace is not None
        assert highlevel is not None
        assert lowlevel is not None

        dsm_obj_name = dsmObjName()
        dsm_obj_name.fs = str_to_bytes(filespace)
        dsm_obj_name.hl = str_to_bytes(highlevel)
        dsm_obj_name.ll = str_to_bytes(lowlevel)
        dsm_obj_name.objType = DSM_OBJ_FILE
        mc_bind_key = mcBindKey()
        mc_bind_key.stVersion = mcBindKeyVersion

        self.method_proxy.dsmBindMC.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmBindMC(self.dsm_handle, ctypes.byref(dsm_obj_name), dsmSendTypeEnum.stArchive,
                                         ctypes.byref(mc_bind_key))
        self._raise_err_on_rc(rc)
        return dsm_obj_name

    @log_execution_time
    def _send_obj(self, dsm_obj_name, filename):
        """
        The dsmSendObj function call starts a request to send a single object to storage. +Multiple dsmSendObj calls
        and associated dsmSendData calls can be made within the bounds of a transaction for performance reasons.

        :param dsm_obj_name: Object returned from bind_mc function
        :param filename: The file to be sent
        """
        assert dsm_obj_name is not None
        assert os.path.exists(filename)

        obj_attr = ObjAttr()
        obj_attr.stVersion = ObjAttrVersion

        size = os.path.getsize(filename)
        if size == 0:
            raise TSMError('size of: {0} is 0 bytes.'.format(filename), rc=None)

        hi, lo = convert_size_to_hi_lo(size)
        logger.info('obj size={0} => hi={1}, low={2}'.format(size, hi, lo))
        obj_attr.sizeEstimate.hi = hi
        obj_attr.sizeEstimate.lo = lo
        obj_attr.objCompressed = dsmFalse
        obj_attr.objInfoLength = 17  # todo
        obj_attr.objInfo = str_to_bytes('test-api-objinfo')

        snd_arch_data = sndArchiveData()
        snd_arch_data.stVersion = sndArchiveDataVersion

        data_blk = DataBlk()
        data_blk.stVersion = DataBlkVersion

        self.method_proxy.dsmSendObj.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmSendObj(self.dsm_handle,
                                          dsmSendTypeEnum.stArchive,
                                          ctypes.byref(snd_arch_data),
                                          ctypes.byref(dsm_obj_name),
                                          ctypes.byref(obj_attr),
                                          ctypes.byref(data_blk))
        if rc == DSM_RC_WILL_ABORT:
            self._end_send_obj()
            self._end_tx()
        else:
            self._raise_err_on_rc(rc)

    @log_execution_time
    def _send_data(self, filename):
        """
        The dsmSendData function call sends a byte stream of data to Tivoli Storage Manager through a buffer.
        The application client can pass any type of data for storage on the server.
        Usually, this data is file data, but it is not limited to such.
        You can call dsmSendData several times, if the byte stream of data that you want to send is large.
        :param filename: Path to file being sent.

        """
        assert filename is not None
        assert os.path.exists(filename)

        logger.info('using send_buffer_len={0} bytes'.format(self.send_buffer_len))

        size = os.path.getsize(filename)
        if size == 0:
            raise TSMError('size of: {0} is 0 bytes.'.format(filename), rc=None)
        logger.info('size of file={0} is: {1} bytes'.format(filename, size))
        bytes_left = size
        start = datetime.datetime.now()

        data_blk = DataBlk()
        data_blk.stVersion = DataBlkVersion
        buff = ctypes.create_string_buffer(self.send_buffer_len)
        data_blk.bufferPtr = ctypes.cast(buff, ctypes.POINTER(ctypes.c_char))

        done = False
        self.method_proxy.dsmSendData.errcheck = self.log_dsm_rc_msg()
        with open(filename, 'rb') as f:
            while not done:
                if bytes_left < self.send_buffer_len:
                    send_amount = bytes_left
                else:
                    send_amount = self.send_buffer_len

                data_blk.bufferLen = send_amount
                data_blk.numBytes = 0  # changed, when send is done
                data = f.read(send_amount)
                logger.info('read {0} bytes from file'.format(send_amount))
                buff.raw = data
                rc = self.method_proxy.dsmSendData(self.dsm_handle, ctypes.byref(data_blk))
                if rc == DSM_RC_WILL_ABORT:
                    self._end_send_obj()
                    self._end_tx()
                else:
                    self._raise_err_on_rc(rc)

                logger.info('{0} bytes of {1} bytes remaining, {2}%...'.format(
                    bytes_left, size, round((100.0 / float(size)) * (size - bytes_left), 2)))

                if send_amount < self.send_buffer_len:  # todo: raussprung muss geprueft werden
                    done = True
                bytes_left = bytes_left - send_amount
        end = datetime.datetime.now()
        elapsed = end - start
        logger.info('sending finished, rate: {0}/s'.format(
            calculate_rate_human_readable(size, elapsed.total_seconds())))
        logger.info('sending took: {0} s'.format(elapsed.total_seconds()))

    @log_execution_time
    def _end_send_obj(self):
        """
        The dsmEndSendObj function call indicates the end of data that is sent to storage.

        Enter the dsmEndSendObj function call to indicate the end of data from the dsmSendObj and dsmSendData calls.
        A protocol violation occurs if this is not performed.
        The exception to this rule is if you call dsmEndTxn to end the transaction.
        Doing this discards all data that was sent for the transaction.
        """
        end_send_obj_ex_out = dsmEndSendObjExOut_t()
        end_send_obj_ex_out.stVersion = dsmEndSendObjExOutVersion

        end_send_obj_ex_in = dsmEndSendObjExIn_t()
        end_send_obj_ex_in.stVersion = dsmEndSendObjExInVersion
        end_send_obj_ex_in.dsmHandle = self.dsm_handle

        self.method_proxy.dsmEndSendObjEx.errcheck = self.log_dsm_rc_msg()
        self.method_proxy.dsmEndSendObjEx(ctypes.byref(end_send_obj_ex_in), ctypes.byref(end_send_obj_ex_out))
        return convert_hi_lo_to_size(hi=end_send_obj_ex_out.totalBytesSent.hi,
                                     lo=end_send_obj_ex_out.totalBytesSent.lo)

    @log_execution_time
    def _end_tx(self, vote=DSM_VOTE_COMMIT):
        """
        The dsmEndTxn function call ends a Tivoli Storage Manager transaction.
        Pair the dsmEndTxn function call with dsmBeginTxn to identify the call or
        set of calls that are considered a transaction.
        The application client can specify on the dsmEndTxn call whether or not
        the transaction should be committed or ended.

        Perform all of the following calls within the bounds of a transaction:

        dsmSendObj
        dsmSendData
        dsmEndSendObj
        dsmDeleteObj
        """
        txn_reason = dsUint16_t(0)
        txn_reason_p = ctypes.pointer(txn_reason)

        self.method_proxy.dsmEndTxn.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmEndTxn(self.dsm_handle, vote, txn_reason_p)
        if txn_reason.value != 0:
            logger.warning('txn reason: {0}'.format(translate_rc_to_mnemonic(txn_reason.value)))
        self._raise_err_on_rc(rc)

    @log_execution_time
    def _begin_query(self, filespace, highlevel, lowlevel):
        """
        The dsmBeginQuery function call starts a query request to the server for information
        about one of the following items:

        Archived data
        Backed-up data
        Active backed-up data
        File spaces
        Management classes.
        :param filespace: The filespace name associated for this object
        :param highlevel: The highlevel name associated for this object
        :param lowlevel: The lowlevel name associated for this object
        """
        assert filespace is not None
        assert highlevel is not None
        assert lowlevel is not None

        obj_name = dsmObjName()
        obj_name.fs = str_to_bytes(filespace)
        obj_name.hl = str_to_bytes(highlevel)
        obj_name.ll = str_to_bytes(lowlevel)
        obj_name.objType = DSM_OBJ_FILE

        archive_data = qryArchiveData()
        archive_data.stVersion = qryArchiveDataVersion
        archive_data.objName = ctypes.pointer(obj_name)
        archive_data.insDateLowerBound.year = DATE_MINUS_INFINITE
        archive_data.insDateUpperBound.year = DATE_PLUS_INFINITE
        archive_data.expDateLowerBound.year = DATE_MINUS_INFINITE
        archive_data.expDateUpperBound.year = DATE_PLUS_INFINITE
        archive_data_p = ctypes.pointer(archive_data)

        logger.info('querying for DSM_OBJ_FILE, DATE_MINUS_INFINITE - DATE_PLUS_INFINITE: fs={0}, hl={1}, '
                    'll={2}...'.format(filespace, highlevel, lowlevel))

        self.method_proxy.dsmBeginQuery.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmBeginQuery(self.dsm_handle, dsmQueryTypeEnum.qtArchive, archive_data_p)
        self._raise_err_on_rc(rc)

    @log_execution_time
    def _get_next_query_obj(self):
        """
        The dsmGetNextQObj function call gets the next query response from a previous dsmBeginQuery
        call and places it in the caller's buffer.
        The dsmGetNextQObj call is called one or more times.
        Each time it is called, a single query record is retrieved.
        If the application client needs to end the query before retrieving all of the data,
        you can send a dsmEndQuery call.
        :return: Returns namedtuple of type (obj_id, size_estimate)
        """

        resp_archive = qryRespArchiveData()
        resp_archive.stVersion = qryRespArchiveDataVersion

        data_blk = DataBlk()
        data_blk.stVersion = DataBlkVersion
        data_blk.bufferLen = ctypes.sizeof(qryRespArchiveData)

        # pointer
        resp_archive_p = ctypes.pointer(resp_archive)
        data_blk.bufferPtr = ctypes.cast(resp_archive_p, ctypes.POINTER(ctypes.c_char))

        found_objs = []
        done = False

        self.method_proxy.dsmGetNextQObj.errcheck = self.log_dsm_rc_msg()

        logger.info('begin query')
        while not done:
            rc = self.method_proxy.dsmGetNextQObj(self.dsm_handle, ctypes.byref(data_blk))
            if rc == DSM_RC_ABORT_NO_MATCH:
                return []
            if rc != DSM_RC_MORE_DATA and rc != DSM_RC_FINISHED:
                self._raise_err_on_rc(rc)
            if (rc == DSM_RC_MORE_DATA or rc == DSM_RC_FINISHED) and data_blk.numBytes:
                logger.info('# found object:')
                logger.info('objId.lo: {0}'.format(resp_archive.objId.lo))
                logger.info('objId.hi: {0}'.format(resp_archive.objId.hi))
                logger.info('objName fs/hl/ll: {0}{1}{2}'.format(bytes_to_str(resp_archive.objName.fs),
                                                                 bytes_to_str(resp_archive.objName.hl),
                                                                 bytes_to_str(resp_archive.objName.ll)))
                logger.info('mediaClass: {0}'.format(resp_archive.mediaClass))
                logger.info('sizeEstimate.lo: {0}'.format(resp_archive.sizeEstimate.lo))
                logger.info('sizeEstimate.hi: {0}'.format(resp_archive.sizeEstimate.hi))
                logger.info('insDate.year: {0}'.format(resp_archive.insDate.year))
                logger.info('insDate.month: {0}'.format(resp_archive.insDate.month))
                logger.info('insDate.day: {0}'.format(resp_archive.insDate.day))
                logger.info('insDate.hour: {0}'.format(resp_archive.insDate.hour))
                logger.info('insDate.minute: {0}'.format(resp_archive.insDate.minute))
                logger.info('insDate.second: {0}'.format(resp_archive.insDate.second))

                obj_id = dsStruct64_t()
                obj_id.hi = resp_archive.objId.hi
                obj_id.lo = resp_archive.objId.lo

                size_estimate = dsStruct64_t()
                size_estimate.hi = resp_archive.sizeEstimate.hi
                size_estimate.lo = resp_archive.sizeEstimate.lo

                ins_date = dsmDate()
                ins_date.year = resp_archive.insDate.year
                ins_date.month = resp_archive.insDate.month
                ins_date.day = resp_archive.insDate.day
                ins_date.hour = resp_archive.insDate.hour
                ins_date.minute = resp_archive.insDate.minute
                ins_date.second = resp_archive.insDate.second

                # beware overwritten memory sections while looping over the data,
                # therefore use the newly constructed values
                fs = resp_archive.objName.fs.decode('utf-8')
                hl = resp_archive.objName.hl.decode('utf-8')
                ll = resp_archive.objName.ll.decode('utf-8')
                result = query_result_tuple(obj_id=obj_id, size_estimate=size_estimate, ins_date=ins_date,
                                            fs=fs, hl=hl, ll=ll)
                found_objs.append(result)
            if rc == DSM_RC_FINISHED:
                logger.info('end query')
                done = True
        assert len(found_objs) < 10  # sanity check
        return sorted(found_objs, reverse=True, key=attrgetter('ins_date.year',
                                                               'ins_date.month',
                                                               'ins_date.day',
                                                               'ins_date.hour',
                                                               'ins_date.minute',
                                                               'ins_date.second'))

    @log_execution_time
    def _end_query(self):
        self.method_proxy.dsmEndQuery.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmEndQuery(self.dsm_handle)
        self._raise_err_on_rc(rc)

    @log_execution_time
    def _begin_get_data(self, obj_ids):
        """
        The dsmBeginGetData function call starts a restore or retrieve operation on a list of objects in storage.
        This list of objects is contained in the dsmGetList structure.
        The application creates this list with values from the query that preceded a call to dsmBeginGetData.
        :param obj_ids:
        :return:
        """
        assert obj_ids is not None

        # if its not an array make it so
        try:
            iter(obj_ids)
        except TypeError:
            obj_ids = [obj_ids]

        # obj_id structures must be present with values
        for obj_id in obj_ids:
            if obj_id.lo != 0:
                continue
            else:
                assert obj_id.hi != 0

        # get_list.objId needs a point to an array,
        # therefore populate the array with values
        # noinspection PyCallingNonCallable
        ds_struct_arr = (dsStruct64_t * len(obj_ids))()  # create array
        for i, obj_id in enumerate(obj_ids):
            ds_struct_arr[i].hi = obj_id.hi
            ds_struct_arr[i].lo = obj_id.lo
        ds_struct_arr_p = ctypes.cast(ds_struct_arr, ctypes.POINTER(dsStruct64_t))  # create pointer

        mount_wait = 1  # wait for mounting device

        get_list = dsmGetList()
        get_list.stVersion = dsmGetListVersion
        get_list.numObjId = dsUint32_t(len(obj_ids))  # number of items
        get_list.objId = ds_struct_arr_p  # (ObjID *)rest_ibuff;

        self.method_proxy.dsmBeginGetData.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmBeginGetData(self.dsm_handle, mount_wait, dsmGetTypeEnum.gtArchive,
                                               ctypes.byref(get_list))
        self._raise_err_on_rc(rc)

    @log_execution_time
    def _get_obj(self, obj_id):
        """
        The dsmGetObj function call obtains the requested object data from the Tivoli Storage Manager
        data stream and places it in the caller's buffer.
        The dsmGetObj call uses the object ID to obtain the next object or partial object from the data stream.
        :param obj_id:
        :return:
        """
        assert obj_id is not None

        data_blk = DataBlk()
        data_blk.stVersion = DataBlkVersion
        logger.info('using receive_buffer_len={0} bytes'.format(self.receive_buffer_len))
        data_blk.bufferLen = self.receive_buffer_len
        data_blk.numBytes = 0

        buff = ctypes.create_string_buffer(self.receive_buffer_len)
        data_blk.bufferPtr = ctypes.cast(buff, ctypes.POINTER(ctypes.c_char))

        self.method_proxy.dsmGetObj.errcheck = self.log_dsm_rc_msg()
        logger.info('requesting object data. this may take a while...')
        rc = self.method_proxy.dsmGetObj(self.dsm_handle, ctypes.pointer(obj_id), ctypes.byref(data_blk))
        if rc != DSM_RC_MORE_DATA and rc != DSM_RC_FINISHED:
            self._raise_err_on_rc(rc)
        return data_blk, buff, rc

    @log_execution_time
    def _get_data(self, dest_file, data_blk, buff, size_estimate, rc):
        """
        The dsmGetData function call obtains a byte stream of data from Tivoli Storage Manager
        and place it in the caller's buffer. The application client calls dsmGetData when there
        is more data to receive from a previous dsmGetObj or dsmGetData call.
        :param dest_file: file to save data
        :param data_blk: infos about received data
        :param buff: buffer to hold received bytes
        :param size_estimate: estimated size
        :return:
        """
        assert dest_file is not None
        assert data_blk is not None
        assert buff is not None
        assert rc is not None

        size_estimate64 = convert_hi_lo_to_size(size_estimate.hi, size_estimate.lo)
        sum_bytes = 0
        logger.info('saving data from server to file: {0}'.format(dest_file))
        done = False
        self.method_proxy.dsmGetData.errcheck = self.log_dsm_rc_msg()
        start = datetime.datetime.now()
        with open(dest_file, 'wb') as f:
            while not done:
                if rc != DSM_RC_MORE_DATA and rc != DSM_RC_FINISHED:
                    self._raise_err_on_rc(rc)
                if rc == DSM_RC_MORE_DATA:
                    f.write(buff.raw[:data_blk.numBytes])
                    logger.debug('DSM_RC_MORE_DATA wrote {0} bytes to file'.format(data_blk.numBytes))
                    sum_bytes += data_blk.numBytes

                    # gets new data and sets data_blk.numBytes
                    rc = self.method_proxy.dsmGetData(self.dsm_handle, ctypes.byref(data_blk))

                    logger.info('{0} bytes of {1} bytes received, {2}%...'.format(
                        sum_bytes, size_estimate64, round((float(sum_bytes) / float(size_estimate64)) * 100, 2)))
                if rc == DSM_RC_FINISHED:
                    if data_blk.numBytes:
                        f.write(buff.raw[:data_blk.numBytes])
                        logger.debug('DSM_RC_FINISHED wrote {0} bytes to file'.format(data_blk.numBytes))
                        sum_bytes += data_blk.numBytes
                    logger.info('loop done')
                    done = True
        end = datetime.datetime.now()
        elapsed = end - start
        logger.info('-- wrote {0} bytes'.format(sum_bytes))
        logger.info('receiving finished, rate: {0}/s'.format(calculate_rate_human_readable(size_estimate64,
                                                                                           elapsed.total_seconds())))
        logger.info('receiving took: {0} s'.format(elapsed.total_seconds()))

    @log_execution_time
    def _end_get_obj(self):
        """
        The dsmEndGetObj function call ends a dsmGetObj session that obtains data for a specified object.
        :return:
        """
        self.method_proxy.dsmEndGetObj.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmEndGetObj(self.dsm_handle)
        self._raise_err_on_rc(rc)

    @log_execution_time
    def _end_get_data(self):
        """
        The dsmEndGetData function call ends a dsmBeginGetData session that obtains objects from storage.
        :return:
        """
        self.method_proxy.dsmEndGetData.errcheck = self.log_dsm_rc_msg()
        rc = self.method_proxy.dsmEndGetData(self.dsm_handle)
        self._raise_err_on_rc(rc)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='archive or delete via the tsm api.')
    parser.add_argument('mode', help='a(rchive)/r(etrive)/d(elete)/q(uery)/l(og)')
    parser.add_argument('--file', dest='file', help='path to src or dest file')
    parser.add_argument('--fs', dest='fs', help='filespace')
    parser.add_argument('--hl', dest='hl', help='highlevel')
    parser.add_argument('--ll', dest='ll', help='lowlevel')
    parser.add_argument('--msg', dest='msg', help='message')
    args = parser.parse_args()

    logger.setLevel(logging.INFO)
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    client = TSMApiClient()
    try:
        client.connect()
        session_info = client.query_session_info()
        logger.info('session info:')
        session_info_str = convert_tsm_structure_to_str(session_info)
        logger.info(session_info_str)
        if args.mode == 'a':
            client.archive(filename=args.file,
                           filespace=args.fs,
                           highlevel=args.hl,
                           lowlevel=args.ll)
        if args.mode == 'r':
            client.retrieve(dest_file=args.file,
                            filespace=args.fs,
                            highlevel=args.hl,
                            lowlevel=args.ll)
        if args.mode == 'd':
            client.delete(args.fs, args.hl, args.ll)
        if args.mode == 'q':
            print(client.query(args.fs, args.hl, args.ll))
        if args.mode == 'h':
            client.connect()
            client.close()
        if args.mode == 'ra':
            folder = '/tmp/'
            a1 = tsm_path_tuple(fs='kopal', hl='782eff9f-4aca-4fd3-a7af-fa6656842cd0', ll='mets.xml')
            a2 = tsm_path_tuple(fs='kopal', hl='782eff9f-4aca-4fd3-a7af-fa6656842cd0', ll='aip.zip')
            client.retrieve_all(folder, [a1, a2])
        if args.mode == 'l':
            client.log(args.msg)
    except Exception as err:
        client.close()
        logger.exception(err)
        logger.error(err)
