#!/usr/bin/env python

import ipaddress
import sys
from re import search
from sys import exit
from re import search
from json import loads as jloads
from os import path, chdir
import logging
from logging.handlers import RotatingFileHandler


from splunklib.searchcommands import \
    dispatch, StreamingCommand, Configuration, Option

@Configuration()
class is_ip(StreamingCommand):
    
    def _protocol_v2_option_parser(self, arg):
        # OVERRIDE THE PARSING FUNCTION SO ARGUMENTS ARE NOT SPLIT
        return [arg]

    def setup_logging( self ):
        class level_filter(logging.Filter):
            def __init__(self, level):
                super().__init__()
                self.level = level
            def filter(self, record):
                return record.levelno == self.level
        def set_handler( log, logFormat, logLevel ):
            logHandler = RotatingFileHandler(
                ('../logs/%s.log' % logLevel),
                maxBytes = 25000000,
                backupCount = 3
                )
            logHandler.setFormatter( logFormat )
            
            logHandler.addFilter( level_filter(
                eval( ("logging.%s" % logLevel.upper()) )
                ) )
            log.addHandler( logHandler )
        log = logging.getLogger( "is_ip" )
        log.setLevel( logging.DEBUG )
        logFormat = logging.Formatter( 
            '%(asctime)s  [%(levelname)s]:  %(message)s', 
            "%Y-%m-%d %H:%M:%S"
            )
        set_handler( log, logFormat=logFormat, logLevel="info" )
        set_handler( log, logFormat=logFormat, logLevel="warn" )
        set_handler( log, logFormat=logFormat, logLevel="error" )

        self.log = log

    def parse_args( self ):
        args = self._metadata.__dict__["searchinfo"].__dict__["args"]
        self.log.info( args )
        if len( args ) < 3:
            self.write_error( "isipin: Too few arguments." )
            self.write_error( "isipin: Expected format: isipin kvstore kvstore_ip_field search_ip_field" )
            exit(1)
        self.kvName = str(args[0])
        self.kvField = str(args[1])
        self.queryField = str(args[2])
        self.fieldRenames = []
        arg_len = len( args )
        if arg_len > 3:
            if ((arg_len - 3) % 3) != 0:
                self.write_error( "isipin: Unable to parse optional arguments: %s" % 
                                  (" ".join(args[3:])) )
                self.write_error( "isipin: Optional arguments should be formated as \"field as renamed_field\"" )
                exit(1)
            count = 3
            while count < arg_len:
                if not str( args[(count + 1)] ) in ["AS", "as"]:
                    self.write_error( "isipin: Optional arguments is malformed: %s" % 
                                  (" ".join( args[(count):(count + 3)] )) 
                                  )
                    exit(1)
                self.fieldRenames.append( {args[(count)]:args[(count + 2)]} )
                count = count + 3
            #self.log.info( str(self.fieldRenames) )

    def get_kv( self ):
        try:
            kvMeta = self.service.get( 
                path_segment=( "storage/collections/config/%s" % self.kvName )
                )
        except Exception as errMsg:
            self.write_error( "isipin: HTTP request to Splunk for KV store failed." )
            self.write_error( errMsg.with_traceback() )
            exit(1)
        if kvMeta["status"]  == 404:
            self.write_error( "isipin: KVstore \"%s\" can't be found. Check the spell and/or permission of your KV." % self.kvName )
            exit(1)
        elif kvMeta["status"]  != 200:
            self.write_error( "isipin: Unexpected HTTP response form Splunk when attempting to retrieve KVstore %s" % self.kvName )
            self.write_error( "isipin: HTTP response code was $s" % str(kvMeta["status"]) )
        kvMeta = kvMeta["body"].read().decode("utf-8")
        if search( (".*\"field\.%s" % self.kvField), str(kvMeta) ) is None:
            self.write_error( "isipin: Unable to find field \"%s\" in KVstore \"%s\"." % (self.kvField, self.kvName) )
            exit(1)
        ipField = self.service.get( 
                path_segment=( "storage/collections/data/%s" % self.kvName ),
                fields=( "_key,%s" % self.kvField )
                )["body"].read().decode("utf-8")
        return jloads( ipField )

    def process_ips( self, ipField ):
        ipAddrs = {
            "v6" : {
                "net":{},
                "addr":{}
                },
            "v4" : {
                "net":{},
                "addr":{}
                }
            }
        v4Count = 0
        v6Count = 0
        for entry in ipField:
            tmp = None
            try:
                ip = str(entry[self.kvField])
            except:
                continue
            if search( "^.*/\d+$", ip ):
                try:
                    tmp = ipaddress.ip_network( ip )
                except:
                    continue
                if tmp.version == 6:
                    ipAddrs["v6"]["net"][tmp] = entry["_key"]
                elif tmp.version == 4:
                    ipAddrs["v4"]["net"][tmp] = entry["_key"]
                else:
                    continue
            else:
                # PROCESS NON-NETWORK ADDRESSES
                try:
                    tmp = ipaddress.ip_address( ip )
                except:
                    continue
                if tmp.version == 6:
                    ipAddrs["v6"]["addr"][tmp] = entry["_key"]
                elif tmp.version == 4:
                    ipAddrs["v4"]["addr"][tmp] = entry["_key"]
                else:
                    continue
            if tmp.version == 6:
                v6Count += 1
            else:
                v4Count += 1
        if v4Count + v6Count == 0:
            self.write_error( "isipin: No IP addresses were found in KVstore \"%s\" under field \"%s\"" %\
                              (self.kvName, self.kvField))
            exit(1)
        self.ipaddrs = ipAddrs
        self.processV4Address = False
        self.processV6Address = False
        if v4Count > 0:
            self.processV4Address = True
        if v6Count > 0:
            self.processV6Address = True
        self.log.info( "v6 count %i" % v6Count )
        self.log.info( "v4 count %i" % v4Count )

    def find_ip( self, event ):
        try:
            queryIp = ipaddress.ip_address( event[self.queryField] )
        except:
            self.log.warning( "\"%s\" could not be converted to IP." % str(event[self.kvField]) )
            return event
        
        def _proc_4_or_6( ipVersion, queryIp, event ):
            try:
                key_id = self.ipaddrs[ipVersion]["addr"][queryIp]
                event["kv_key"] = key_id
                return event
            except KeyError:
                pass
            for ipv4Network in self.ipaddrs[ipVersion]["net"].keys():
                if queryIp in ipv4Network:
                    key_id = self.ipaddrs[ipVersion]["net"][ipv4Network]
                    event["kv_key"] = key_id
                    return event
        if queryIp.version == 4 and self.processV4Address:
            self.log.info(str((queryIp.version)))
            return  _proc_4_or_6( "v4", queryIp=queryIp, event=event )
        elif queryIp.version == 6 and self.processV6Address:
            return  _proc_4_or_6( "v6", queryIp=queryIp, event=event )
        else:
            self.log.warning( "IP address module returned unexpected IP version %s for \"%s\" " % \
                             ( str(queryIp.version), str(event[self.kvField]) ) 
                             )
            return event

    def stream(self, events):
        self.setup_logging()
        #self.log.info(str(self.fieldnames))
        self.parse_args()
        ipField = self.get_kv()
        self.process_ips( ipField )
        for event in events:
            self.log.info( type(event) )
            tmp = self.find_ip( event=event )
            self.log.info( type(tmp) )
            yield tmp



chdir( path.dirname( 
       path.abspath(__file__) 
    ) )

dispatch(is_ip, sys.argv, sys.stdin, sys.stdout, __name__)

# | is_ip kvstore ((field1 == field2) OR field) output_field AS renamed, ...
