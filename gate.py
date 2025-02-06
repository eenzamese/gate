"""Addresses filter"""
import socket
import time
import logging
import traceback
import re
import sys
import pathlib
import random
from os import listdir, sep, mkdir
from os.path import isfile, join, dirname, exists

# TODO: correct paths
# constants
APP_TMT = 60
LOG_START_TIME = re.sub(r"\W+", "_", str(time.ctime()))
LOG_FMT_STRING = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

if getattr(sys, 'frozen', False):
    app_path = dirname(sys.executable)
    app_name = pathlib.Path(sys.executable).stem
    APP_RUNMODE = 'PROD'
    time.sleep(APP_TMT)
else:
    app_path = dirname(__file__)
    app_name = pathlib.Path(__file__).stem
    APP_RUNMODE = 'TEST'


INPUT_DIR = f'{app_path}{sep}servers{sep}'
LOG_DIR = f'{app_path}{sep}logs'
if not exists(LOG_DIR):
    mkdir(LOG_DIR)
LOG_FILENAME = f'{LOG_DIR}{sep}{app_name}_{LOG_START_TIME}.log'
log_handlers = [logging.StreamHandler(),logging.FileHandler(LOG_FILENAME)]


logger = logging.getLogger(APP_RUNMODE)
logging.basicConfig(format=LOG_FMT_STRING,
                    datefmt='%d.%m.%Y %H:%M:%S',
                    level=logging.INFO, # NOTSET/DEBUG/INFO/WARNING/ERROR/CRITICAL
                    handlers=log_handlers)


while True:
    result_gates = []
    try:
        logger.info('Searching files in INPUT directory %s', INPUT_DIR)
        onlyfiles = [f for f in listdir(INPUT_DIR) if isfile(join(INPUT_DIR, f))]
        actual_files = max([int(af.split('_')[1]) for af in onlyfiles if 'servers' in af])
        actual_file = [af for af in onlyfiles if str(actual_files) in af]
        direct_file = f"{INPUT_DIR}{actual_file[0]}"
        logger.info('Needed file is %s', direct_file)
        direct_file_out = f"{INPUT_DIR}{actual_file[0]}_out_{str(random.randint(0, 1000))}.txt"
        logger.info('Needed output file is %s', direct_file_out)
        with open(direct_file, 'r', errors='ignore') as file: # pylint: disable=unspecified-encoding
            data_r = file.read()
        data_r = re.findall(r'[0-9]+(?:\.[0-9]+){3}', data_r)
    except Exception as ex: # pylint: disable=broad-exception-caught
        logger.warning(str(ex))
        logger.warning(traceback.format_exc())
        time.sleep(3)
        continue
    for gate_address in data_r:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((gate_address, 443))
        if result == 0:
            str_out = f'Gate address is {gate_address}'
            logger.info(str_out)
            result_gates.append(gate_address)
        else:
            STR_OUT = 'Gate address is FAILED'
            logger.info(STR_OUT)
            continue
        sock.close()
    logger.info('Try to create %s', direct_file_out)
    with open(direct_file_out, 'w') as file: # pylint: disable=unspecified-encoding
        DATA_W = '\n'.join(result_gates)
        file.write(DATA_W)
    STR_OUT = 'State is OK'
    logger.info(STR_OUT)
    time.sleep(1800)
