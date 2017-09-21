# tsm-api-client

A ctypes python wrapper for the IBM Spectrum Protect (SP) (formerly Tivoli Storage Manager) API. 
SP can be used as a low cost object storage backend in case long access/retrieval time does 
not matter.

**Caution:** This code is not fully tested. Improvements are welcome.

# Requirements

* Python >= 3.4
* A pre installed TSM Client [1] and a pre defined [dsm.sys](dsm.sys-sample) file in: /opt/tivoli/tsm/client/ba/bin/dsm.sys

[1] https://www.ibm.com/support/knowledgecenter/SSGSG7_7.1.1/com.ibm.itsm.client.doc/t_inst_linuxx86client.html%23t_inst_linuxx86client

# Sample usage

See also: \__main__ in tsm/client.py

## Archive and Retrieve

    client = TSMApiClient()
    try:
        filename = '/tmp/test.txt'
        filespace = 'TEST'
        
        # filespace name, high-level name, and low-level name are 
        # concatenated, they must form a syntactically correct name 
        # on the operating system on which the client runs
        # see: http://publib.boulder.ibm.com/tividd/td/TSMC/GC32-0793-00/en_US/HTML/ansa0002.htm#ToC_67 
        hl = 'abc'
        ll = 'test.txt'
        
        client.connect()
        info = client.query_session_info()
        print('session info: {}'.format(convert_tsm_structure_to_str(info)))
        client.archive(filename=filename,
                       filespace=filespace,
                       highlevel=hl,
                       lowlevel=ll)
        dest = '/tmp/test_retrieve.txt'
        client.retrieve(dest_file=dest,
                        filespace=filespace,
                        highlevel=hl,
                        lowlevel=ll)
    except TSMError:
        logging.exception()
    finally:
        client.close()

## Query

    client = TSMApiClient()
    try:
        filespace = 'TEST'
        hl = 'abc'
        ll = 'test.txt'
        
        client.connect()
        objs = client.query(filespace=filespace,
                            highlevel=hl,
                            lowlevel=ll)
        for obj in objs:
            print(obj.obj_id)
            print(obj.ins_date)
    except TSMError:
        logging.exception()
    finally:
        client.close()
        
## Delete

    client = TSMApiClient()
    try:
        filespace = 'TEST'
        hl = 'abc'
        ll = 'test.txt'
        
        client.connect()
        client.delete(filespace=filespace,
                      highlevel=hl,
                      lowlevel=ll)
    except TSMError:
        logging.exception()
    finally:
        client.close()