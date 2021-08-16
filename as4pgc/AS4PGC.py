# -*- coding: utf-8 -*-
"""
    AS4PGC.py
    ~~~~~~~~~

    This module contains functions for hiding and recovering files
    using .mp3 audio files.

    :copyright: (c) 2021 by Clark Fieseln.
    :license: MIT License, see LICENSE.md for more details.
"""

"""
    Notes
    ~~~~~
    Warning! Hiding files inside "big MP3 files" (e.g. 3 min.) may take up to one hour.
    ###################################################################################
    The target of this steganographic technique is hiding information in .MP3 audio files instead of using the classical
    LSB-steganography on .WAV files.
    This results in a lower capacity, but an audio format is used, which is much more wide spread and therefore less
    suspicious.
    The main reason it is not possible to directly manipulate "single" samples as in .WAV format 
    is because of changes resulting from conversion in .MP3 format which distort signal manipulations.
    Modifications on single bits of the samples are just too small to survive MP3 conversion reliably.
    Instead, the audio signal is partitioned in small chunks and then the FFT of each chunk is calculated.
    The FFT-series obtained as a result, is manipulated by increasing or decreasing the amplitude of the FFT at specific
    coding-frequencies.
    Coding is done on alternating chunks, using unmodified chunks as reference points.
    A linear interpolation between these reference points determines the threshold between ones and zeros.
    It is important that the FFT-series has consecutive samples that are highly correlated. 
"""



# imports
#########
import copy
import traceback
import soundfile as sf
import matplotlib.pyplot as plt
import shlex,  subprocess
import simpleaudio as sa
import numpy as np
import scipy.io.wavfile as wf
from scipy.fft import rfft, irfft
import math
from inspect import currentframe, getframeinfo
import random
from bitarray import bitarray
from timeit import default_timer as timer
from datetime import timedelta
import logging
import argparse
from getpass import getpass
import os
from dataclasses import dataclass
import configparser
from tinytag import TinyTag
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import zlib
from shutil import copy2
from scipy import signal
from sys import exit



# version
#########
# TODO: import from setup.py or from __init__.py?
#       if we import it from setup.py the help shows "strange default parameters"...
# import setup
# from setup import __version__
__version__ = "1.0.3"

# current frame
###############
cf = currentframe()



# header
########
# Note: HEADER_PAYLOAD_SIZE_BYTES as bytes() will result in encrypted data of size HEADER_SIZE_BYTES
# Header            =  compression_on encryption_on  ,  file_name   ,   size   #   padding
# max. size in bytes         1            1          1      36      1     6    1   (HEADER_PAYLOAD_SIZE_BYTES -
#                                                                                   (len(file_name) + len(size) + 5))
#####################################################################################################################
HEADER_SIZE_BYTES = 140
HEADER_PAYLOAD_SIZE_BYTES = 47
MAX_LEN_MSG_FILE_NAME = 36
# Note: LEVEL_OF_COMPRESSION: 9 highest but slow, 6 default compromise, 1 fast but low compression
LEVEL_OF_COMPRESSION = 9



# argument parser
#################
parser = argparse.ArgumentParser(prog='as4pgc',
                                 usage='%(prog)s -w <message_file> <carrier_file> [options]\n       or\n       %(prog)s -r <stego_file> [options]',
                                 description='Hide message_file (e.g. txt or zip) inside carrier_file (mono .wav, .mp3, .oog, .aac)\nor\nExtract message_file from stego_file.')
group = parser.add_mutually_exclusive_group()
group.add_argument('-w', "--write", action='store', type=str, nargs=2, help='<path and name of file with secret message (any type)> <path and name of file used as a carrier to embed the secret message file (.mp3 mono or stereo)>', metavar='')
parser.add_argument('-f', "--output_file", action='store', type=str, help='(-w) path and name of stego output file of type .mp3 or (-r) name of message output file', metavar='')
parser.add_argument('-e', "--encryption", action='store_true', help='encrypt the secret message before hiding it')
group.add_argument('-r', "--read", action='store', type=str, help='<path and name of stego file with hidden secret message (e.g. type .mp3 mono)>', metavar='')
parser.add_argument('-v', "--verbose", action='store_true', help='display details during program execution')
parser.add_argument('-l', "--verbose_level", action='store', type=str, choices={"info","warning","error","critical","debug"}, help=': info, warning, error, critical, debug', metavar='')
parser.add_argument('-p', "--plot", action='store_true', help='show plots')
parser.add_argument('-s', "--sound", action='store_true', help='play stego output file')
parser.add_argument('-a', "--hide", action='store_true', help='hide output file using attrib')
group.add_argument('-d', "--defaultconfig", action='store_true', help='create default config.ini and exit (file can be edited to customize) - when used together with -m config.ini is messed-up with the password')
parser.add_argument('-m', "--messupconfig", action='store_true', help='mess up configuration as derived from password (needs to be used in both write and read calls)')
parser.add_argument('-V', "--version", action='version', version="%(prog)s " + __version__, help='show version and exit')
# parse arguments
# with options -h or -V the program exits after next code-line
##############################################################
args = parser.parse_args()



# arguments?
############
if args.defaultconfig == False\
    and\
    isinstance(args.write, type(None))\
    and\
    isinstance(args.read, type(None)):
    print("You need to provide some option, for help type: as4pgc -h")
    exit(cf.f_lineno)

# write(=hide) or read(=recover) files
######################################
message_file = ""
carrier_file = ""
stego_file = ""
WRITE = False
if not isinstance(args.write, type(None)):
    message_file = args.write[0]
    carrier_file = args.write[1]
    WRITE = True
elif not isinstance(args.read, type(None)):
    stego_file = args.read

# logging
#########
# LOGGING_LEVEL specifies the lowest-severity log message a logger will handle, where debug is the lowest built-in severity level and critical is the highest built-in severity.
# For example, if the severity level is INFO, the logger will handle only INFO, WARNING, ERROR, and CRITICAL messages and will ignore DEBUG messages.
DO_LOG = args.verbose
if args.verbose == False:
    # set DO_LOG to true anyways...logging level will be set to ERROR in this case
    DO_LOG = True
if not isinstance(args.verbose_level, type(None)):
    LOGGING_LEVEL = args.verbose_level
    LOGGING_LEVEL = "logging." + LOGGING_LEVEL.upper()
else:
    if args.verbose == False:
        LOGGING_LEVEL = "logging.ERROR"
    else:
        # -v provided but no level specified, take INFO as default in that case
        LOGGING_LEVEL = "logging.INFO"

logging_level = logging.ERROR # logging.INFO
if LOGGING_LEVEL == "logging.DEBUG":
    logging_level = logging.DEBUG
elif LOGGING_LEVEL == "logging.INFO":
    logging_level = logging.INFO
elif LOGGING_LEVEL == "logging.WARNING":
    logging_level = logging.WARNING
elif LOGGING_LEVEL == "logging.ERROR":
    logging_level = logging.ERROR
elif LOGGING_LEVEL == "logging.CRITICAL":
    logging_level = logging.CRITICAL

if args.verbose == False:
    # we activate it anyways with default logging.ERROR but, in this case we dont want to make it
    # look like a log, so we remove the timestamp
    logging.basicConfig(format='%(message)s', datefmt='%H:%M:%S', level=logging_level)
else:
    logging.basicConfig(format='%(asctime)s.%(msecs)03d %(message)s', datefmt='%H:%M:%S', level=logging_level)

logger = logging.getLogger()
logger.disabled = not DO_LOG
logging.info(args)
logging.info("DO_LOG = " + str(DO_LOG))
logging.info("LOGGING_LEVEL = " + str(LOGGING_LEVEL))



# module variable containing
#     - hardcoded default configuration
#     - configuration read from config.ini
#     - configuration partially derived from password
###############################################################
@dataclass
class Configuration:
    # normal configuration:
    #######################
    CHUNK_LEN_SAMPLES: int
    MAX_VOLUME: float
    SEED_IGNORE: int
    SEED_IGNORE_CODE_DECEPTION: int
    SEED_THRESHOLD: int # TODO: implement code using this..
    IGNORE_THRESHOLD: float
    DO_IGNORE_SOME: bool
    DO_DECEPTION: bool
    BSF_MIN_ATTENUATION_DB: int
    SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT: float
    SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT: float
    INTERLEAVED_CHUNKS: int
    INTERLEAVED_FC: int
    SAMPLING_FREQUENCY: int
    NORMALIZE_SETTINGS: bool
    MAX_NR_OF_ITERATIONS: int
    # advanced configuration:
    #########################
    CODE_FREQUENCY_START_BIN: int
    CODE_FREQUENCY_END_BIN: int
    CHECK_IMAG_TOO: bool
    KEEP_TEMP_FILES: bool
    MP3_BITRATE: int
    INTERPOLATE_AND_DUMMY_CODE_ALL: bool
    AVG_INTERPOLATION: bool
    INTERPOLATE_WITH_MEAN: bool
    CODE_WITH_MAGNITUDE: bool
    RECODE_FACTOR_PLUS: float
    CODE_FACTOR_PERCENT: float
    CODE_FACTOR_PERCENT_DETECTION_THRESHOLD: float
    FFMPEG_VERSION: str

# Note: these default values will be used in case we can't read or there is no config.ini
#########################################################################################
configuration = Configuration(
    # basic configuration:
    ######################
    480, # 960, # 480,  # CHUNK_LEN_SAMPLES
    0.75, # MAX_VOLUME
    77, # SEED_IGNORE
    78, # SEED_IGNORE_CODE_DECEPTION
    79, # SEED_THRESHOLD
    0.99, # IGNORE_THRESHOLD - 0.99 will result in approx. 1% of bits being NOT coded
    True, # DO_IGNORE_SOME
    True, # DO_DECEPTION
    20, # BSF_MIN_ATTENUATION_DB
    0.0083, # SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT - depends on NORMALIZE_SETTINGS
    9999.9, # 0.1000, # SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT - depends on NORMALIZE_SETTINGS
    2, # INTERLEAVED_CHUNKS
    2, # INTERLEAVED_FC
    48000,  # SAMPLING_FREQUENCY
    True,  # NORMALIZE_SETTINGS
    250,  # MAX_NR_OF_ITERATIONS
    # advanced configuration:
    #########################
    120, # 240, # 120, # CODE_FREQUENCY_START_BIN
    189, # 239 # 359 # 399, # 199, # CODE_FREQUENCY_END_BIN
    True, # CHECK_IMAG_TOO
    False, # KEEP_TEMP_FILES
    320000, # MP3_BITRATE
    False, # INTERPOLATE_AND_DUMMY_CODE_ALL
    False, # AVG_INTERPOLATION
    True, # INTERPOLATE_WITH_MEAN
    True, # CODE_WITH_MAGNITUDE
    1.15, # RECODE_FACTOR_PLUS
    70.0, # CODE_FACTOR_PERCENT
    40.0, # CODE_FACTOR_PERCENT_DETECTION_THRESHOLD
    "4.4-full_build-www.gyan.dev") # FFMPEG_VERSION

# configparser
##############
config = configparser.ConfigParser(allow_no_value=True)
config_filename = "config.ini"

# if option -d provided, then force creation of default config.ini
# by renaming the current config.ini and storing a backup as old.config.ini
###########################################################################
if args.defaultconfig == True:
    if os.path.isfile(config_filename):
        if os.path.isfile('old.' + config_filename):
            os.remove('old.' + config_filename)
            logging.info("Deleted old." + config_filename)
        os.rename(config_filename, 'old.'+config_filename)
        logging.info("Created backup of "+config_filename+" as old."+config_filename)
else:
    logging.info("Reading " + config_filename + "...")

# Load the configuration file
#############################
if os.path.isfile(config_filename):
    try:
        config.read(config_filename)
        logging.info("    Sections: " + config.sections().__str__())
        if "myConfig" in config:
            logging.info("    Keys in section myConfig:")
            if "CHUNK_LEN_SAMPLES" in config["myConfig"]:
                configuration.CHUNK_LEN_SAMPLES = int(config['myConfig']['CHUNK_LEN_SAMPLES'])
                logging.info("        configuration.CHUNK_LEN_SAMPLES = " + configuration.CHUNK_LEN_SAMPLES.__str__())
            if "MAX_VOLUME" in config["myConfig"]:
                configuration.MAX_VOLUME = float(config['myConfig']['MAX_VOLUME'])
                logging.info("        configuration.MAX_VOLUME = " + configuration.MAX_VOLUME.__str__())
            if "SEED_IGNORE" in config["myConfig"]:
                configuration.SEED_IGNORE = int(config['myConfig']['SEED_IGNORE'])
                logging.info("        configuration.SEED_IGNORE = " + configuration.SEED_IGNORE.__str__())
            if "SEED_IGNORE_CODE_DECEPTION" in config["myConfig"]:
                configuration.SEED_IGNORE_CODE_DECEPTION = int(config['myConfig']['SEED_IGNORE_CODE_DECEPTION'])
                logging.info("        configuration.SEED_IGNORE_CODE_DECEPTION = " + configuration.SEED_IGNORE_CODE_DECEPTION.__str__())
            if "SEED_THRESHOLD" in config["myConfig"]:
                configuration.SEED_THRESHOLD = int(config['myConfig']['SEED_THRESHOLD'])
                logging.info("        configuration.SEED_THRESHOLD = " + configuration.SEED_THRESHOLD.__str__())
            if "IGNORE_THRESHOLD" in config["myConfig"]:
                configuration.IGNORE_THRESHOLD = float(config['myConfig']['IGNORE_THRESHOLD'])
                logging.info("        configuration.IGNORE_THRESHOLD = " + configuration.IGNORE_THRESHOLD.__str__())
            if "DO_IGNORE_SOME" in config["myConfig"]:
                configuration.DO_IGNORE_SOME = config.getboolean('myConfig','DO_IGNORE_SOME')
                logging.info("        configuration.DO_IGNORE_SOME = " + configuration.DO_IGNORE_SOME.__str__())
            if "DO_DECEPTION" in config["myConfig"]:
                configuration.DO_DECEPTION = config.getboolean('myConfig','DO_DECEPTION')
                logging.info("        configuration.DO_DECEPTION = " + configuration.DO_DECEPTION.__str__())
            if "BSF_MIN_ATTENUATION_DB" in config["myConfig"]:
                configuration.BSF_MIN_ATTENUATION_DB = int(config['myConfig']['BSF_MIN_ATTENUATION_DB'])
                logging.info("        configuration.BSF_MIN_ATTENUATION_DB = " + configuration.BSF_MIN_ATTENUATION_DB.__str__())
            if "SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT" in config["myConfig"]:
                configuration.SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT = float(config['myConfig']['SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT'])
                logging.info("        configuration.SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT = " + configuration.SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT.__str__())
            if "SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT" in config["myConfig"]:
                configuration.SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT = float(config['myConfig']['SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT'])
                logging.info("        configuration.SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT = " + configuration.SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT.__str__())
            if "INTERLEAVED_CHUNKS" in config["myConfig"]:
                configuration.INTERLEAVED_CHUNKS = int(config['myConfig']['INTERLEAVED_CHUNKS'])
                logging.info("        configuration.INTERLEAVED_CHUNKS = " + configuration.INTERLEAVED_CHUNKS.__str__())
            if "INTERLEAVED_FC" in config["myConfig"]:
                configuration.INTERLEAVED_FC = int(config['myConfig']['INTERLEAVED_FC'])
                logging.info("        configuration.INTERLEAVED_FC = " + configuration.INTERLEAVED_FC.__str__())
            if "SAMPLING_FREQUENCY" in config["myConfig"]:
                configuration.SAMPLING_FREQUENCY = int(config['myConfig']['SAMPLING_FREQUENCY'])
                logging.info("        configuration.SAMPLING_FREQUENCY = " + configuration.SAMPLING_FREQUENCY.__str__())
            if "NORMALIZE_SETTINGS" in config["myConfig"]:
                configuration.NORMALIZE_SETTINGS = config.getboolean('myConfig', 'NORMALIZE_SETTINGS')
                logging.info("        configuration.NORMALIZE_SETTINGS = " + configuration.NORMALIZE_SETTINGS.__str__())
            if "MAX_NR_OF_ITERATIONS" in config["myConfig"]:
                configuration.MAX_NR_OF_ITERATIONS = int(config['myConfig']['MAX_NR_OF_ITERATIONS'])
                logging.info("        configuration.MAX_NR_OF_ITERATIONS = " + configuration.MAX_NR_OF_ITERATIONS.__str__())
        if "myAdvancedConfig" in config:
            logging.info("    Keys in section myAdvancedConfig:")
            if "CODE_FREQUENCY_START_BIN" in config["myAdvancedConfig"]:
                configuration.CODE_FREQUENCY_START_BIN = int(config['myAdvancedConfig']['CODE_FREQUENCY_START_BIN'])
                logging.info("        configuration.CODE_FREQUENCY_START_BIN = " + configuration.CODE_FREQUENCY_START_BIN.__str__())
            if "CODE_FREQUENCY_END_BIN" in config["myAdvancedConfig"]:
                configuration.CODE_FREQUENCY_END_BIN = int(config['myAdvancedConfig']['CODE_FREQUENCY_END_BIN'])
                logging.info("        configuration.CODE_FREQUENCY_END_BIN = " + configuration.CODE_FREQUENCY_END_BIN.__str__())
            if "CHECK_IMAG_TOO" in config["myAdvancedConfig"]:
                configuration.CHECK_IMAG_TOO = config.getboolean('myAdvancedConfig', 'CHECK_IMAG_TOO')
                logging.info("        configuration.CHECK_IMAG_TOO = " + configuration.CHECK_IMAG_TOO.__str__())
            if "KEEP_TEMP_FILES" in config["myAdvancedConfig"]:
                configuration.KEEP_TEMP_FILES = config.getboolean('myAdvancedConfig', 'KEEP_TEMP_FILES')
                logging.info("        configuration.KEEP_TEMP_FILES = " + configuration.KEEP_TEMP_FILES.__str__())
            if "MP3_BITRATE" in config["myAdvancedConfig"]:
                configuration.MP3_BITRATE = int(config['myAdvancedConfig']['MP3_BITRATE'])
                logging.info("        configuration.MP3_BITRATE = " + configuration.MP3_BITRATE.__str__())
            if "INTERPOLATE_AND_DUMMY_CODE_ALL" in config["myAdvancedConfig"]:
                configuration.INTERPOLATE_AND_DUMMY_CODE_ALL = config.getboolean('myAdvancedConfig', 'INTERPOLATE_AND_DUMMY_CODE_ALL')
                logging.info("        configuration.INTERPOLATE_AND_DUMMY_CODE_ALL = " + configuration.INTERPOLATE_AND_DUMMY_CODE_ALL.__str__())
            if "AVG_INTERPOLATION" in config["myAdvancedConfig"]:
                configuration.AVG_INTERPOLATION = config.getboolean('myAdvancedConfig', 'AVG_INTERPOLATION')
                logging.info("        configuration.AVG_INTERPOLATION = " + configuration.AVG_INTERPOLATION.__str__())
            if "INTERPOLATE_WITH_MEAN" in config["myAdvancedConfig"]:
                configuration.INTERPOLATE_WITH_MEAN = config.getboolean('myAdvancedConfig', 'INTERPOLATE_WITH_MEAN')
                logging.info("        configuration.INTERPOLATE_WITH_MEAN = " + configuration.INTERPOLATE_WITH_MEAN.__str__())
            if "CODE_WITH_MAGNITUDE" in config["myAdvancedConfig"]:
                configuration.CODE_WITH_MAGNITUDE = config.getboolean('myAdvancedConfig', 'CODE_WITH_MAGNITUDE')
                logging.info("        configuration.CODE_WITH_MAGNITUDE = " + configuration.CODE_WITH_MAGNITUDE.__str__())
            if "RECODE_FACTOR_PLUS" in config["myAdvancedConfig"]:
                configuration.RECODE_FACTOR_PLUS = float(config['myAdvancedConfig']['RECODE_FACTOR_PLUS'])
                logging.info("        configuration.RECODE_FACTOR_PLUS = " + configuration.RECODE_FACTOR_PLUS.__str__())
            if "CODE_FACTOR_PERCENT" in config["myAdvancedConfig"]:
                configuration.CODE_FACTOR_PERCENT = float(config['myAdvancedConfig']['CODE_FACTOR_PERCENT'])
                logging.info("        configuration.CODE_FACTOR_PERCENT = " + configuration.CODE_FACTOR_PERCENT.__str__())
            if "CODE_FACTOR_PERCENT_DETECTION_THRESHOLD" in config["myAdvancedConfig"]:
                configuration.CODE_FACTOR_PERCENT_DETECTION_THRESHOLD = float(config['myAdvancedConfig']['CODE_FACTOR_PERCENT_DETECTION_THRESHOLD'])
                logging.info("        configuration.CODE_FACTOR_PERCENT_DETECTION_THRESHOLD = " + configuration.CODE_FACTOR_PERCENT_DETECTION_THRESHOLD.__str__())
            if "FFMPEG_VERSION" in config["myAdvancedConfig"]:
                configuration.FFMPEG_VERSION = str(config['myAdvancedConfig']['FFMPEG_VERSION'])
                logging.info("        configuration.FFMPEG_VERSION = " + configuration.FFMPEG_VERSION.__str__())
    except (configparser.NoSectionError, configparser.MissingSectionHeaderError):
        logging.info("Error: Exception raised in AS4PGC.py trying to load config file!")
        logging.info("       Default values will be used. Activate verbose mode with -v to see default values.\n")
        pass
    except Exception:
        traceback.print_exc()
        exit(cf.f_lineno)

# plausibility checks
#####################
if configuration.CODE_FREQUENCY_END_BIN <= configuration.CODE_FREQUENCY_START_BIN:
    logging.error("Error: CODE_FREQUENCY_END_BIN <= CODE_FREQUENCY_START_BIN")
    exit(cf.f_lineno)

# ffmpeg version
################
command = "ffmpeg -version"
p1 = subprocess.Popen(shlex.split(command), shell=False, stdout=subprocess.PIPE)
out, err = p1.communicate()
FFMPEG_VERSION = configuration.FFMPEG_VERSION
if p1.returncode == 0:
    ffmpeg_ver_idx_start = out.__str__().find("ffmpeg version")
    if ffmpeg_ver_idx_start >= 0:
        ffmpeg_ver_idx_start = ffmpeg_ver_idx_start + len("ffmpeg version") + 1
        ffmpeg_ver_idx_end = ffmpeg_ver_idx_start + out.__str__()[ffmpeg_ver_idx_start:].find(" ")
        FFMPEG_VERSION = out.__str__()[ffmpeg_ver_idx_start:ffmpeg_ver_idx_end]
        if configuration.FFMPEG_VERSION != FFMPEG_VERSION:
            configuration.FFMPEG_VERSION = FFMPEG_VERSION
            print("Warning: FFMPEG_VERSION does not contain the correct ffmpeg version = "+FFMPEG_VERSION)
            print("         Remember you need to use the same codec when extracting the hidden message!")
else:
    logging.error("Error: could not get ffmpeg version!")
    exit(cf.f_lineno)
p1.terminate()
p1.kill()
logging.info("FFMPEG_VERSION = "+FFMPEG_VERSION+"(used only for plausibility check)")

# mess-up config?
# NOTE: if no pwd is provided but -m was passed
#       then we use empty pwd as password.
###############################################
MESS_UP_CONFIG = args.messupconfig
logging.info("MESS_UP_CONFIG = " + str(MESS_UP_CONFIG))

# password
# used for:
#   encryption of the message file (if option -e provided)
#   setting random seeds (if not empty)
#   encryption of the header
#   messing-up configuration (if option -m provided)
##################################################################
try_count = 3
while (True):
    PASSWORD = getpass("pwd: ")
    if WRITE:
        pwd_conf = getpass("confirm pwd: ")
    else:
        pwd_conf = PASSWORD
    if PASSWORD == pwd_conf:
        # Note: if we use a random number here we must make sure that it is equal when reading,
        #       this is not posssible with urandom() so we hardcode it
        ##############################################################
        salt = bytes(b'salt') # os.urandom(16)
        kdf = PBKDF2HMAC(algorithm = hashes.SHA256(),length = 32,salt = salt,iterations = 100000,)
        KEY_FROM_PASSWORD = base64.urlsafe_b64encode(kdf.derive(bytearray(PASSWORD,"utf-8")))
        fernet = Fernet(KEY_FROM_PASSWORD)
        # derive new seeds from key
        # use first and second part of key to generate 2 different integers
        # NOTE: with this, correct decoding does NOT only depend on config.ini but also on password
        ###########################################################################################
        if PASSWORD != "":
            configuration.SEED_IGNORE = int.from_bytes(KEY_FROM_PASSWORD[:len(KEY_FROM_PASSWORD)//2], byteorder='little', signed=False)
            configuration.SEED_IGNORE_CODE_DECEPTION = int.from_bytes(KEY_FROM_PASSWORD[len(KEY_FROM_PASSWORD)//2:], byteorder='little', signed=False)
            logging.info("configuration.SEED_IGNORE derived from password = " + str(configuration.SEED_IGNORE))
            logging.info("configuration.SEED_IGNORE_CODE_DECEPTION derived from password = " + str(configuration.SEED_IGNORE_CODE_DECEPTION))
        elif MESS_UP_CONFIG == False:
            # Note: no password and no argument -m provided
            #       the unmodified seeds may be the hardcoded-default-values or may come from config.ini
            #       We still have some randomness derived from deception[] and ignore[] which will generate different .mp3 files
            #       in each iteration, resulting in small variations during normalization/scaling of the audio signal.
            logging.warning("Warning: no pwd provided, unmodified seeds will be used.")
        if WRITE == True:
            print("You'll need this password to recover the embedded message, keep it safe!")
        break
    else:
        try_count = try_count - 1
        if try_count == 0:
            logging.error("Error: incorrect password confirmation. Max. nr. of retries exceeded.")
            exit(cf.f_lineno)
        else:
            logging.error("Error: incorrect password confirmation, try again.")

# mess up configuration
#######################
if MESS_UP_CONFIG == True:
    idx_key = 0
    len_key = len(KEY_FROM_PASSWORD)
    logging.info("Start messing up with configuration based on password..")
    configuration.CHUNK_LEN_SAMPLES = configuration.CHUNK_LEN_SAMPLES + int(KEY_FROM_PASSWORD[idx_key])
    logging.info("Messed configuration.CHUNK_LEN_SAMPLES = "+str(configuration.CHUNK_LEN_SAMPLES))
    ##### MAX_VOLUME
    idx_key = (idx_key + 1)%len_key
    configuration.SEED_IGNORE = int.from_bytes(KEY_FROM_PASSWORD[:len(KEY_FROM_PASSWORD) // 2], byteorder='little',signed=False)
    logging.info("Messed up configuration.SEED_IGNORE = " + str(configuration.SEED_IGNORE))
    configuration.SEED_IGNORE_CODE_DECEPTION = int.from_bytes(KEY_FROM_PASSWORD[len(KEY_FROM_PASSWORD) // 2:],byteorder='little', signed=False)
    logging.info("Messed up configuration.SEED_IGNORE_CODE_DECEPTION = " + str(configuration.SEED_IGNORE_CODE_DECEPTION))
    configuration.SEED_THRESHOLD = int(KEY_FROM_PASSWORD[idx_key])
    logging.info("Messed up configuration.SEED_THRESHOLD = " + str(configuration.SEED_THRESHOLD))
    idx_key = (idx_key + 1) % len_key
    configuration.IGNORE_THRESHOLD = 0.99 + (float(KEY_FROM_PASSWORD[idx_key])/255.0)/100.0
    logging.info("Messed up configuration.IGNORE_THRESHOLD = " + str(configuration.IGNORE_THRESHOLD))
    idx_key = (idx_key + 1) % len_key
    ##### DO_IGNORE_SOME: bool
    ##### DO_DECEPTION: bool
    ##### BSF_MIN_ATTENUATION_DB: int
    ##### SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT: float
    ##### SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT: float
    ##### INTERLEAVED_CHUNKS: int
    ##### INTERLEAVED_FC: int
    ##### SAMPLING_FREQUENCY: int
    ##### NORMALIZE_SETTINGS: bool
    ##### MAX_NR_OF_ITERATIONS: int
    #CODE_FREQUENCY_START_BIN: int
    random.seed(int(KEY_FROM_PASSWORD[idx_key]))
    diff_bins = configuration.CODE_FREQUENCY_END_BIN - configuration.CODE_FREQUENCY_START_BIN
    configuration.CODE_FREQUENCY_START_BIN = configuration.CODE_FREQUENCY_START_BIN + random.randint(-configuration.CODE_FREQUENCY_START_BIN//20, configuration.CODE_FREQUENCY_START_BIN//10)
    logging.info("Messed up configuration.CODE_FREQUENCY_START_BIN = " + str(configuration.CODE_FREQUENCY_START_BIN))
    idx_key = (idx_key + 1) % len_key
    random.seed(int(KEY_FROM_PASSWORD[idx_key]))
    configuration.CODE_FREQUENCY_END_BIN = configuration.CODE_FREQUENCY_START_BIN + diff_bins + random.randint(-diff_bins//10, diff_bins//5)
    logging.info("Messed up configuration.CODE_FREQUENCY_END_BIN = " + str(configuration.CODE_FREQUENCY_END_BIN))
    idx_key = (idx_key + 1) % len_key
    #### CHECK_IMAG_TOO: bool
    #### KEEP_TEMP_FILES: bool
    #### MP3_BITRATE: int
    #### INTERPOLATE_AND_DUMMY_CODE_ALL: bool
    #### AVG_INTERPOLATION: bool                     #### good candidate to mess-up
    #### INTERPOLATE_WITH_MEAN: bool                 #### good candidate to mess-up
    #### CODE_WITH_MAGNITUDE: bool                     ## could mess-up this as well
    #### RECODE_FACTOR_PLUS: float
    #### CODE_FACTOR_PERCENT: float
    #### CODE_FACTOR_PERCENT_DETECTION_THRESHOLD: float
    #### FFMPEG_VERSION: str
    logging.info("Finished messing up with configuration based on password..")

# config_filename does not exist
################################
if not os.path.isfile(config_filename):
    config.add_section('myConfig')
    config.add_section('myAdvancedConfig')
    # basic configuration:
    ######################
    config['myConfig']['CHUNK_LEN_SAMPLES'] = str(configuration.CHUNK_LEN_SAMPLES)
    config['myConfig']['MAX_VOLUME'] = str(configuration.MAX_VOLUME)
    config['myConfig']['SEED_IGNORE'] = str(configuration.SEED_IGNORE)
    config['myConfig']['SEED_IGNORE_CODE_DECEPTION'] = str(configuration.SEED_IGNORE_CODE_DECEPTION)
    config['myConfig']['SEED_THRESHOLD'] = str(configuration.SEED_THRESHOLD)
    config['myConfig']['IGNORE_THRESHOLD'] = str(configuration.IGNORE_THRESHOLD)
    config['myConfig']['DO_IGNORE_SOME'] = str(configuration.DO_IGNORE_SOME)
    config['myConfig']['DO_DECEPTION'] = str(configuration.DO_DECEPTION)
    config['myConfig']['BSF_MIN_ATTENUATION_DB'] = str(configuration.BSF_MIN_ATTENUATION_DB)
    config['myConfig']['SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT'] = str(configuration.SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT)
    config['myConfig']['SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT'] = str(configuration.SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT)
    config['myConfig']['INTERLEAVED_CHUNKS'] = str(configuration.INTERLEAVED_CHUNKS)
    config['myConfig']['INTERLEAVED_FC'] = str(configuration.INTERLEAVED_FC)
    config['myConfig']['SAMPLING_FREQUENCY'] = str(configuration.SAMPLING_FREQUENCY)
    config['myConfig']['NORMALIZE_SETTINGS'] = str(configuration.NORMALIZE_SETTINGS)
    config['myConfig']['MAX_NR_OF_ITERATIONS'] = str(configuration.MAX_NR_OF_ITERATIONS)
    # advanced configuration:
    #########################
    config['myAdvancedConfig']['CODE_FREQUENCY_START_BIN'] = str(configuration.CODE_FREQUENCY_START_BIN)
    config['myAdvancedConfig']['CODE_FREQUENCY_END_BIN'] = str(configuration.CODE_FREQUENCY_END_BIN)
    config['myAdvancedConfig']['CHECK_IMAG_TOO'] = str(configuration.CHECK_IMAG_TOO)
    config['myAdvancedConfig']['KEEP_TEMP_FILES'] = str(configuration.KEEP_TEMP_FILES)
    config['myAdvancedConfig']['MP3_BITRATE'] = str(configuration.MP3_BITRATE)
    config['myAdvancedConfig']['INTERPOLATE_AND_DUMMY_CODE_ALL'] = str(configuration.INTERPOLATE_AND_DUMMY_CODE_ALL)
    config['myAdvancedConfig']['AVG_INTERPOLATION'] = str(configuration.AVG_INTERPOLATION)
    config['myAdvancedConfig']['INTERPOLATE_WITH_MEAN'] = str(configuration.INTERPOLATE_WITH_MEAN)
    config['myAdvancedConfig']['CODE_WITH_MAGNITUDE'] = str(configuration.CODE_WITH_MAGNITUDE)
    config['myAdvancedConfig']['RECODE_FACTOR_PLUS'] = str(configuration.RECODE_FACTOR_PLUS)
    config['myAdvancedConfig']['CODE_FACTOR_PERCENT'] = str(configuration.CODE_FACTOR_PERCENT)
    config['myAdvancedConfig']['CODE_FACTOR_PERCENT_DETECTION_THRESHOLD'] = str(configuration.CODE_FACTOR_PERCENT_DETECTION_THRESHOLD)
    config['myAdvancedConfig']['FFMPEG_VERSION'] = str(configuration.FFMPEG_VERSION)
    # created default config.ini? then exit..
    #########################################
    if args.defaultconfig == True:
        # create default config file
        with open(config_filename, 'w') as configfile:
            # write new settings into file
            config.write(configfile)
            print("Created default config.ini")
        exit(cf.f_lineno)
    else:
        logging.info("No config.ini, we use default values.")
        # TODO: uncomment next code-block to always force creation...
        #       for now we dont want to have this file if not really required, this shall keep things simpler.
        '''
        # create default config file
        with open(config_filename, 'w') as configfile:
            # write new settings into file
            config.write(configfile)
            print("Created default config.ini")
        # '''

# check if files exist
######################
if WRITE == True:
    if not os.path.isfile(message_file):
        logging.error("Error: message file " + message_file + " not found!")
        exit(cf.f_lineno)
    if not os.path.isfile(carrier_file):
        logging.error("Error: carrier file " + carrier_file + " not found!")
        exit(cf.f_lineno)
else:
    if not os.path.isfile(stego_file):
        logging.error("Error: stego file " + stego_file + " not found!")
        exit(cf.f_lineno)

NORMALIZE_SETTINGS = configuration.NORMALIZE_SETTINGS
logging.info("NORMALIZE_SETTINGS = " + str(NORMALIZE_SETTINGS))
CHECK_IMAG_TOO = configuration.CHECK_IMAG_TOO
logging.info("CHECK_IMAG_TOO = " + str(CHECK_IMAG_TOO))
FILE_NAME_HDR = ""

if WRITE:
    if ".mp3" not in carrier_file:
        print("Error: carrier file shall be .mp3 type")
        exit(cf.f_lineno)
    CARRIER_FILE_NAME = carrier_file
    logging.info("CARRIER_FILE_NAME = " + CARRIER_FILE_NAME)
    # Note: output directory of carrier also used as temp dir
    index_of_last_slash = CARRIER_FILE_NAME.rfind('/')
    OUT_DIR_NAME = CARRIER_FILE_NAME[:index_of_last_slash+1] # +1 to include the slash
    logging.info("OUT_DIR_NAME (also used as directory for temporary files) = " + OUT_DIR_NAME)
    MESSAGE_FILE_NAME = message_file
    logging.info("MESSAGE_FILE_NAME = " + MESSAGE_FILE_NAME)
    if not isinstance(args.output_file, type(None)):
        OUT_FILE_NAME = args.output_file
    else:
        OUT_FILE_NAME = OUT_DIR_NAME + "stego.mp3"
    logging.info("OUT_FILE_NAME = " + OUT_FILE_NAME)
    # COMPRESSION may be set to True later if it really brings a reduction in msg length
    COMPRESSION = False
    # NOTE: if no pwd is provided but -e was passed
    #       then we use the empty pwd as password.
    ###############################################
    if not isinstance(args.encryption, type(None)):
        ENCRYPTION = args.encryption
    else:
        ENCRYPTION = False
    logging.info("ENCRYPTION = " + str(ENCRYPTION))
    index_of_last_slash = CARRIER_FILE_NAME.rfind('/')
    index_of_last_point = CARRIER_FILE_NAME.rfind('.')
    FILE_NAME = OUT_DIR_NAME + CARRIER_FILE_NAME[index_of_last_slash+1:index_of_last_point]
    # Note: dont use any path...the path will be given when reading,
    #       then we use the same path as the path of the input file.
    ################################################################
    index_of_last_slash = MESSAGE_FILE_NAME.rfind('/')
    FILE_NAME_HDR = MESSAGE_FILE_NAME[index_of_last_slash + 1:]
    if len(FILE_NAME_HDR) > MAX_LEN_MSG_FILE_NAME:
        logging.error("Error: max. length of message file name = "+str(MAX_LEN_MSG_FILE_NAME))
        exit(cf.f_lineno)
    index_of_last_point = OUT_FILE_NAME.rfind('.')
    index_of_last_point2 = MESSAGE_FILE_NAME.rfind('.')
    OUT_MESSAGE_FILE_NAME = OUT_FILE_NAME[:index_of_last_point] + MESSAGE_FILE_NAME[index_of_last_point2:]
else:
    # Note: directory of stego file also used as output dir for extracting message file
    index_of_last_slash = stego_file.rfind('/')
    OUT_DIR_NAME = stego_file[:index_of_last_slash+1] # +1 to include the slash
    if not isinstance(args.output_file, type(None)):
        if len(args.output_file) <= MAX_LEN_MSG_FILE_NAME:
            if "/" not in args.output_file:
                FILE_NAME_HDR = args.output_file
            else:
                logging.error("Error: file name shall not contain path.")
                exit(cf.f_lineno)
        else:
            logging.error("Error: max. length of file name = 36.")
            exit(cf.f_lineno)

MAX_NR_OF_ITERATIONS = configuration.MAX_NR_OF_ITERATIONS
logging.info("MAX_NR_OF_ITERATIONS = " + str(MAX_NR_OF_ITERATIONS))
#############
# NOTE: SCALING audio signal to MAX_VOLUME may be used before "normalizing" signals in order to always use similar
#       configuration settings. High values of MAX_VOLUME are especially useful in signals with low level,
#       which otherwise hide less bits.
# WARNING: scaling, as well as other signal manipulations such as adding noise, a tone, or saturation will affect
#       the .MP3 result irreversibly. Note: adding noise reduces correlation between chunks, this is not good.
#       *** DO NOT SCALE if you intend to UNSCALE after coding...that will destroy coding ***
################################################################################################
SCALE_INPUT = True
logging.info("SCALE_INPUT = " + str(SCALE_INPUT))
###############################################
# TODO: if adding noise is useful (e.g. to hide coding) then create corresponding configuration parameters (type, level,..).
#       Investigate if e.g. it is necessary to filter noise before addition.
# Note: adding noise is irreversible, and it may affect correlations between consecutive chunks which reduces coding capacity.
#       when NOISE_LEVEL = 0.001, noise max value is 1000 times smaller than max. (with max 32768 we code up to 32 approx, which is 5 bits)
#       when NOISE_LEVEL = 0.0001, noise max value is 10000 times smaller than max. (with max 32768 we code up to 3.2 approx, which is 2 bits)
#       NOISE_LEVEL = 0.0 means noise is NOT added
LEVEL_ADDED_NOISE = 0.0 # 0.01 # 0.001 # 0.0001
###############################################
KEEP_TEMP_FILES = configuration.KEEP_TEMP_FILES
PLAY_ON = args.sound
DO_PLOT = args.plot
HIDE = args.hide
PLOT_SIG = True and DO_PLOT
PLOT_FFT = True and DO_PLOT
PLOT_CDF = True and DO_PLOT
PLOT_ERR = True and DO_PLOT
PLOT_3D = False and DO_PLOT # just a test, but it seems to be extremely slow!
PLOT_BIT_ERR_IN_ITERATIONS = True and DO_PLOT
# Note: no matter which sampling rate the input file has, we force the output to SAMPLING_FREQUENCY.
SAMPLING_FREQUENCY = configuration.SAMPLING_FREQUENCY
NYQUIST_FREQUENCY = (SAMPLING_FREQUENCY/2.0)
NUM_CHANNELS = 1
BYTES_PER_SAMPLE = 2
BITS_PER_SAMPLE = 8*BYTES_PER_SAMPLE
MAX_AMPLITUDE = 2**(BITS_PER_SAMPLE-1)
MP3_BITRATE = configuration.MP3_BITRATE
MP3_BITRATE_STR = str(MP3_BITRATE)
# 32-bit floating reduces digitizing errors but is probably not supported by other tools
MP3_SAMPLE_FORMAT = "flt"  # "s16" # "dbl"
WAV_SAMPLE_FORMAT = "pcm_f32le"  # "pcm_s16le"
CHUNK_LEN_SAMPLES = configuration.CHUNK_LEN_SAMPLES
# Note: MAX_VOLUME is applied when SCALE_INPUT = True (see comments there)
#       MAX_VOLUME shall probably not exceed 0.9 so there is still room for tolerances, coding, etc.
MAX_VOLUME = configuration.MAX_VOLUME
if MAX_VOLUME > 1.0:
    print("Error: MAX_VOLUME > 1.0")
    exit(cf.f_lineno)
# Note: INTERLEAVED_CHUNKS, required for chunk-interpolation, may also help "spreading" the message across
#       the carrier (in time domain) in order to keep statistics and be robust against steganalysis.
INTERLEAVED_CHUNKS = configuration.INTERLEAVED_CHUNKS
if INTERLEAVED_CHUNKS < 2:
    print("Error: INTERLEAVED_CHUNKS < 2")
    exit(cf.f_lineno)
# Note: INTERLEAVED_FC, sometimes needed to separate coded frequencies and avoid interferences, may also help
#       "spreading" the message across the carrier (in frequency domain) in order to keep
#       statistics and be robust against steganalysis.
INTERLEAVED_FC = configuration.INTERLEAVED_FC
if INTERLEAVED_FC < 1:
    print("Error: INTERLEAVED_FC < 1")
    exit(cf.f_lineno)
# Note: on use of INTERPOLATE_AND_DUMMY_CODE_ALL
#       if all chunks are interpolated, the statistics will be more regular and therefore more difficult to detect with
#       steganalysis. If only the part of the message is interpolated, then we reduce noise noticeably and
#       may even shorten iterations, but then we affect audio statistics.
INTERPOLATE_AND_DUMMY_CODE_ALL = configuration.INTERPOLATE_AND_DUMMY_CODE_ALL
logging.info("SAMPLING_FREQUENCY = " + str(SAMPLING_FREQUENCY))
logging.info("MP3_BITRATE_STR = " + MP3_BITRATE_STR)
logging.info("CHUNK_LEN_SAMPLES = " + str(CHUNK_LEN_SAMPLES))
logging.info("MAX_VOLUME = " + str(MAX_VOLUME))
logging.info("INTERLEAVED_CHUNKS = " + str(INTERLEAVED_CHUNKS))
logging.info("INTERLEAVED_FC = " + str(INTERLEAVED_FC))
logging.info("INTERPOLATE_AND_DUMMY_CODE_ALL = " + str(INTERPOLATE_AND_DUMMY_CODE_ALL))
AVG_INTERPOLATION = configuration.AVG_INTERPOLATION
logging.info("AVG_INTERPOLATION = " + str(AVG_INTERPOLATION))
INTERPOLATE_WITH_MEAN = configuration.INTERPOLATE_WITH_MEAN
logging.info("INTERPOLATE_WITH_MEAN = " + str(INTERPOLATE_WITH_MEAN))
###################################################
DO_IGNORE_SOME = configuration.DO_IGNORE_SOME
DO_DECEPTION = configuration.DO_DECEPTION
SEED_IGNORE = configuration.SEED_IGNORE
# SEED_IGNORE_CODE_DECEPTION also used to init dummy bits for padding after message (for cases with no encryption).
SEED_IGNORE_CODE_DECEPTION = configuration.SEED_IGNORE_CODE_DECEPTION
# IGNORE_THRESHOLD -> = 0.99 will result in approx. 1% of bits being NOT coded in order to confuse attacker.
IGNORE_THRESHOLD = configuration.IGNORE_THRESHOLD
SEED_THRESHOLD = configuration.SEED_THRESHOLD
logging.info("DO_IGNORE_SOME = " + str(DO_IGNORE_SOME))
logging.info("DO_DECEPTION = " + str(DO_DECEPTION))
logging.info("SEED_IGNORE = " + str(SEED_IGNORE))
logging.info("SEED_IGNORE_CODE_DECEPTION = " + str(SEED_IGNORE_CODE_DECEPTION))
logging.info("IGNORE_THRESHOLD = " + str(IGNORE_THRESHOLD))
logging.info("SEED_THRESHOLD = " + str(SEED_THRESHOLD))
##################################################
SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT = configuration.SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT
SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT = configuration.SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT
logging.info("SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT = " + str(SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT))
logging.info("SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT = " + str(SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT))
###################################################
# Note: if CODE_WITH_MAGNITUDE = False, then we code only with .real values
CODE_WITH_MAGNITUDE = configuration.CODE_WITH_MAGNITUDE
logging.info("CODE_WITH_MAGNITUDE = " + str(CODE_WITH_MAGNITUDE))
FFT_BIN_WIDTH_HZ = int(NYQUIST_FREQUENCY/(CHUNK_LEN_SAMPLES/2))
logging.info("FFT_BIN_WIDTH_HZ = "+str(FFT_BIN_WIDTH_HZ))
NR_OF_FFT_BINS = int(NYQUIST_FREQUENCY/FFT_BIN_WIDTH_HZ)
logging.info("NR_OF_FFT_BINS = "+str(NR_OF_FFT_BINS)+" (0->"+str(FFT_BIN_WIDTH_HZ)+"Hz, "+str(FFT_BIN_WIDTH_HZ)+"->"+str(FFT_BIN_WIDTH_HZ*2)+"Hz,...)")
###################################################
FREQUENCY = np.zeros(NR_OF_FFT_BINS)
for f in range(len(FREQUENCY)):
    FREQUENCY[f] = FFT_BIN_WIDTH_HZ*f
    logging.info("FREQUENCY["+str(f)+"] = "+str(FREQUENCY[f]))
CODE_FREQUENCY = np.zeros(NR_OF_FFT_BINS)
CODE_FREQUENCY_BIN = np.zeros(NR_OF_FFT_BINS, dtype=int)
for i in range(len(CODE_FREQUENCY)):
    CODE_FREQUENCY[i] = FFT_BIN_WIDTH_HZ*i
    CODE_FREQUENCY_BIN[i] = int(CODE_FREQUENCY[i]/FFT_BIN_WIDTH_HZ)
    logging.info("CODE_FREQUENCY["+str(i)+"] = "+str(CODE_FREQUENCY[i]))
    logging.info("CODE_FREQUENCY_BIN[" + str(i) + "] = " + str(CODE_FREQUENCY_BIN[i]))
###################################################
# Note:
#      coding between 12kHz and 20kHz seems to work fine when output 320k .mp3
#      Below 12kHz we get too much hearable noise, above 20kHz signal is too weak.
##################################################################################
if configuration.CODE_FREQUENCY_START_BIN < NR_OF_FFT_BINS:
    CODE_FREQUENCY_START_BIN = configuration.CODE_FREQUENCY_START_BIN
else:
    CODE_FREQUENCY_START_BIN = NR_OF_FFT_BINS//2
if configuration.CODE_FREQUENCY_END_BIN <= NR_OF_FFT_BINS:
    CODE_FREQUENCY_END_BIN = configuration.CODE_FREQUENCY_END_BIN
else:
    CODE_FREQUENCY_END_BIN = NR_OF_FFT_BINS-1
CODE_FREQUENCY_START = CODE_FREQUENCY[CODE_FREQUENCY_START_BIN]
CODE_FREQUENCY_END = CODE_FREQUENCY[CODE_FREQUENCY_END_BIN]
NR_OF_CODE_FREQUENCIES = (CODE_FREQUENCY_END_BIN - CODE_FREQUENCY_START_BIN) + 1
logging.info("CODE_FREQUENCY_START = " + str(CODE_FREQUENCY_START))
logging.info("CODE_FREQUENCY_START_BIN = " + str(CODE_FREQUENCY_START_BIN))
logging.info("CODE_FREQUENCY_END = " + str(CODE_FREQUENCY_END))
logging.info("CODE_FREQUENCY_END_BIN = " + str(CODE_FREQUENCY_END_BIN))
logging.info("NR_OF_CODE_FREQUENCIES = " + str(NR_OF_CODE_FREQUENCIES))
###################################################
# Example for coding ABOVE interpolated reference:
##################################################
#
#     code  (is approx. CODE_FACTOR_PERCENT % above interpolation-ref.)
#     (o)
#                                \
#                                 }  ABS(code - interp) % shall be approx. CODE_FACTOR_PERCENT %
#                                /
#     (*) interp
#
RECODE_FACTOR_PLUS = configuration.RECODE_FACTOR_PLUS
RECODE_FACTOR_MINUS = RECODE_FACTOR_PLUS
CODE_FACTOR_PERCENT = configuration.CODE_FACTOR_PERCENT
# Note: values below CODE_FACTOR_PERCENT_DETECTION_THRESHOLD will be SKIPPED.
CODE_FACTOR_PERCENT_DETECTION_THRESHOLD = configuration.CODE_FACTOR_PERCENT_DETECTION_THRESHOLD
if CODE_FACTOR_PERCENT_DETECTION_THRESHOLD >= CODE_FACTOR_PERCENT:
    logging.info("Configuration ERROR: CODE_FACTOR_PERCENT_DETECTION_THRESHOLD >= CODE_FACTOR_PERCENT. We will skip all coded bits!")
    exit(cf.f_lineno)
if CODE_FACTOR_PERCENT > 100:
    logging.info("Configuration ERROR: CODE_FACTOR_PERCENT shall not exceed 100, otherwise lower delta cannot be coded!")
    exit(cf.f_lineno)
elif CODE_FACTOR_PERCENT == 0:
    logging.info("Configuration WARNING: with CODE_FACTOR_PERCENT == 0 coding will actually remove frequencies completely or double them, depending on ONE, ZERO value!")
CODE_FACTOR_PERCENT_PLUS_DEFAULT = (100.0 + CODE_FACTOR_PERCENT) / 100.0
CODE_FACTOR_PERCENT_MINUS_DEFAULT = (100.0 - CODE_FACTOR_PERCENT) / 100.0
logging.info("RECODE_FACTOR_PLUS = "+str(RECODE_FACTOR_PLUS))
logging.info("RECODE_FACTOR_MINUS = "+str(RECODE_FACTOR_MINUS))
logging.info("CODE_FACTOR_PERCENT = "+str(CODE_FACTOR_PERCENT))
logging.info("CODE_FACTOR_PERCENT_DETECTION_THRESHOLD = "+str(CODE_FACTOR_PERCENT_DETECTION_THRESHOLD))
logging.info("CODE_FACTOR_PERCENT_PLUS_DEFAULT = "+str(CODE_FACTOR_PERCENT_PLUS_DEFAULT))
logging.info("CODE_FACTOR_PERCENT_MINUS_DEFAULT = "+str(CODE_FACTOR_PERCENT_MINUS_DEFAULT))
# avoid peaks / big deviations and silences
###########################################
INTERPOLATION_FACTOR_PERCENT = CODE_FACTOR_PERCENT_DETECTION_THRESHOLD
INTERPOLATION_FACTOR_PERCENT_PLUS = (100.0 + INTERPOLATION_FACTOR_PERCENT) / 100.0
INTERPOLATION_FACTOR_PERCENT_MINUS = (100.0 - INTERPOLATION_FACTOR_PERCENT) / 100.0
logging.info("INTERPOLATION_FACTOR_PERCENT = "+str(INTERPOLATION_FACTOR_PERCENT))
logging.info("INTERPOLATION_FACTOR_PERCENT_MINUS = "+str(INTERPOLATION_FACTOR_PERCENT_MINUS))
##################
# NOTE: used to restore CODE_FACTOR_PERCENT_PLUS and CODE_FACTOR_PERCENT_MINUS after use in recode
CODE_FACTOR_PERCENT_PLUS_OLD = CODE_FACTOR_PERCENT_PLUS_DEFAULT
CODE_FACTOR_PERCENT_MINUS_OLD = CODE_FACTOR_PERCENT_MINUS_DEFAULT

# settings "band stop filter" to not interfere coding frequency when writing
############################################################################
# settings "elliptic filter"
# set BSF_MIN_ATTENUATION_DB = 0 to deactivate band stop filter
BSF_MIN_ATTENUATION_DB = configuration.BSF_MIN_ATTENUATION_DB
if BSF_MIN_ATTENUATION_DB > 145:
    logging.error("Error: BSF_MIN_ATTENUATION_DB too high. Max. = 145 dB")
    exit(cf.f_lineno)
elif BSF_MIN_ATTENUATION_DB > 0:
    logging.info("Applying the band-stop-filter to the input signal will worsen concealing in frequency domain,\n\
            thus increasing vulnerability against steganalysis. Apply this option only as a last measure.")
BSF_LEFT_MARGIN = 400 # 600
BSF_RIGHT_MARGIN = 400 # 600
BSF_ORDER = 7
BSF_MAX_RIPPLE = 0.1
BSF_F1 = CODE_FREQUENCY_START - BSF_LEFT_MARGIN
BSF_F2 = CODE_FREQUENCY_END + BSF_RIGHT_MARGIN
# TODO: update filter range each time we change NR_OF_CODE_FREQUENCIES_TO_CODE (and MAX_NR_OF_CODE_FREQUENCIES) ?
if BSF_F2 > FREQUENCY[NR_OF_FFT_BINS-1]:
    BSF_F2 = FREQUENCY[NR_OF_FFT_BINS-1]

# code message
##############
message_temp = bitarray()
header_as_string = ""

# IMPORTANT: use SystemRandom() which uses os.urandom() internally to provide
#            "secure" random numbers while still calling functions in random module (which is insecure).
# NOTE: results are no longer "reproducible", i.e. they are different in each run.
########################################################################################################
system_random = random.SystemRandom()
system_random.seed(SEED_IGNORE_CODE_DECEPTION)

# if writing:
#     append header and input message to message_temp
#####################################################
if WRITE == True:
    # compression
    #############
    len_msg_compressed = 0
    with open(MESSAGE_FILE_NAME, 'rb') as fh:
        a_bitarray = bitarray()
        a_bitarray.fromfile(fh)
        a_bytes = a_bitarray.tobytes()
        a_bytes_compressed = zlib.compress(a_bytes, LEVEL_OF_COMPRESSION)
        len_msg_compressed = len(a_bytes_compressed)
        if len_msg_compressed < len(a_bytes):
            COMPRESSION = True
            compression_ratio = float(len(a_bytes)) / float(len_msg_compressed)
            logging.info("Compressed msg with ratio = "+str(compression_ratio))
        else:
            logging.debug("No compression applied with len_msg_compressed = "+str(len_msg_compressed))
    # encryption
    ############
    if ENCRYPTION == False:
        if COMPRESSION == True:
            LEN_MSG_BYTES = len_msg_compressed + HEADER_SIZE_BYTES
        else:
            LEN_MSG_BYTES = os.path.getsize(MESSAGE_FILE_NAME) + HEADER_SIZE_BYTES
    else:
        if COMPRESSION == True:
            a_bytes = a_bytes_compressed
        a_bytes_encrypted = fernet.encrypt(a_bytes)
        LEN_MSG_BYTES = len(a_bytes_encrypted) + HEADER_SIZE_BYTES
    # add data to header which is needed later to recover the message
    #################################################################
    header_as_string += str(int(COMPRESSION == True))
    header_as_string += str(int(ENCRYPTION==True))
    header_as_string += "," + FILE_NAME_HDR
    # add comma as field separator
    header_as_string += "," + str(LEN_MSG_BYTES)
    # add end marker
    header_as_string += "#"
    # transform str -> bytes
    configuration_as_bytes = bytes(header_as_string, "utf-8")
    # add padding bytes (as secure random bytes)
    if len(configuration_as_bytes) <= HEADER_PAYLOAD_SIZE_BYTES:
        padding = os.urandom(HEADER_PAYLOAD_SIZE_BYTES - len(configuration_as_bytes))
    else:
        logging.error("Error: configuration in header too big!")
        exit(cf.f_lineno)
    # to use # as a separator it shall NOT appear in the padding
    # if it does, we re-generate padding until it does not.
    ############################################################
    while b'#' in padding:
        padding = os.urandom(HEADER_PAYLOAD_SIZE_BYTES - len(configuration_as_bytes))
    # Note: after next call, configuration_as_bytes will have size HEADER_PAYLOAD_SIZE_BYTES
    configuration_as_bytes = configuration_as_bytes + padding
    # Note: after next call, configuration_as_encrypted_bytes will have size HEADER_SIZE_BYTES
    configuration_as_encrypted_bytes = fernet.encrypt(configuration_as_bytes)
    # header too big?
    if len(configuration_as_encrypted_bytes) != HEADER_SIZE_BYTES:
        logging.error("Error: incorrect header size!")
        exit(cf.f_lineno)
    # copy header bytes to a bitarray message
    message_temp.frombytes(configuration_as_encrypted_bytes)
    # append actual secret message to bitarray message with header
    ##############################################################
    if ENCRYPTION == False:
        if COMPRESSION == True:
            message_temp.frombytes(a_bytes_compressed)
        else:
            message_temp.frombytes(a_bytes)
    else:
        message_temp.frombytes(a_bytes_encrypted)



# print_progress()
##################
# Print progress bar
# example from https://stackoverflow.com/questions/3173320/text-progress-bar-in-the-console
# changed fill due to unicode encoding error
# def print_progress (iteration, total, prefix = '', suffix = '', decimals = 1, bar_length = 100, fill = '█', printEnd = "\r"):
def print_progress(iteration, total, prefix='', suffix='', decimals=1, bar_length=100, fill='#', printEnd="\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 * (iteration / float(total)))
    filledLength = int(bar_length * iteration // total)
    bar = fill * filledLength + '-' * (bar_length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}', end = printEnd)
    # Print New Line on Complete
    if iteration == total:
        print()



# write()
#     hide message in carrier and output result in stego file
#############################################################
def write():
    # time measurement
    ##################
    start = timer()

    print("Embedding secret message...")

    # local variables
    #################
    SKIP_CODING_IF_MIN_EXCEEDED = SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT
    SKIP_CODING_IF_MAX_EXCEEDED = SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT
    CODE_FACTOR_PERCENT_PLUS = CODE_FACTOR_PERCENT_PLUS_DEFAULT
    CODE_FACTOR_PERCENT_MINUS = CODE_FACTOR_PERCENT_MINUS_DEFAULT
    # flag to run last iteration again and activate final PLOTs
    ###########################################################
    DO_LAST = False

    # log write
    ###########
    cf = currentframe()
    filename = getframeinfo(cf).filename
    logging.info("(Line nr. "+str(cf.f_lineno)+") Enter write() function in file: " + filename)

    # extract .mp3 metadata for info only
    #####################################
    tag = TinyTag.get(FILE_NAME + ".mp3")
    logging.info(stego_file+" metadata:")
    logging.info("    duration in seconds = "+str(tag.duration))
    logging.info("    samplerate = " + str(tag.samplerate))
    logging.info("    bitrate = " + str(tag.bitrate))
    logging.info("    channels = " + str(tag.channels))
    logging.info("    comment = " + str(tag.comment))

    # mono?
    #######
    if tag.channels != 1:
        logging.warning("Warning: no mono input file! Output will be converted to mono.")

    # convert input file in .mp3 format to .wav to make it readable by code
    # TODO: solve Issue: [B603:subprocess_without_shell_equals_true] subprocess call - check for execution of untrusted input.
    #             Severity: Low   Confidence: High
    ##########################################################################################################################
    if tag.channels == 1:
        command = "ffmpeg -loglevel quiet -y -i " + FILE_NAME + ".mp3 -vn -acodec "+WAV_SAMPLE_FORMAT+" -ac 1 -ar "+str(SAMPLING_FREQUENCY)+" -f wav " + FILE_NAME + ".wav"
    else:
        command = "ffmpeg -loglevel quiet -y -i " + FILE_NAME + ".mp3 -vn -acodec "+WAV_SAMPLE_FORMAT+" -ac 2 -ar " + str(SAMPLING_FREQUENCY) + " -f wav " + FILE_NAME + "_temp.wav"
    p1 = subprocess.Popen(shlex.split(command), shell=False, stdout=subprocess.PIPE)
    out, err = p1.communicate()
    if p1.returncode == 0:
        pass
    else:
        logging.error("Error: could not run ffmpeg!")
        exit(cf.f_lineno)
    p1.terminate()
    p1.kill()
    logging.info("Converted " + FILE_NAME + ".mp3 to " + FILE_NAME + ".wav")

    # stereo to mono
    ################
    if tag.channels == 2:
        command = "ffmpeg -loglevel quiet -y -i " + FILE_NAME + "_temp.wav -map_channel 0.0.0 " + FILE_NAME + ".wav"
        p1 = subprocess.Popen(shlex.split(command), shell=False, stdout=subprocess.PIPE)
        out, err = p1.communicate()
        if p1.returncode == 0:
            pass
        else:
            logging.error("Error: could not run ffmpeg!")
            exit(cf.f_lineno)
        p1.terminate()
        p1.kill()
        logging.info("Converted " + FILE_NAME + "_temp.wav stereo to " + FILE_NAME + ".wav mono")
        # del _temp.wav
        ###############
        if os.path.exists(FILE_NAME+"_temp.wav"):
            os.remove(FILE_NAME+"_temp.wav")
            logging.info("Deleted " + FILE_NAME + "_temp.wav")

    # read sig <- .wav
    ##################
    sig3, samplerate = sf.read(FILE_NAME + ".wav")
    logging.info("Read " + FILE_NAME + ".wav as sig3")
    logging.info("Nr. of samples of sig3 = " + str(len(sig3)))

    # add noise?
    ############
    if LEVEL_ADDED_NOISE > 0.0:
        noise = np.zeros(len(sig3))
        for i in range(len(sig3)):
            noise[i] = (system_random.random()*2 - 1)*LEVEL_ADDED_NOISE
        noise_max = max(abs(noise))
        sig3_max = max(abs(sig3))
        if sig3_max + noise_max > 1.0:
            sig3 = sig3 - (1-sig3_max)
        sig3 = sig3 + noise
        logging.info("Added noise with amplitude "+str(LEVEL_ADDED_NOISE))

    # apply band-stop filter?
    #########################
    if BSF_MIN_ATTENUATION_DB > 0:
        sos_bandstop = signal.ellip(BSF_ORDER, BSF_MAX_RIPPLE, BSF_MIN_ATTENUATION_DB,
                                         # Note: we need to divide by Nyquist frequency or pass fs as argument...one thing or the other..
                                         # [BPF_F1 / audioSettings.NYQUIST_FREQUENCY, BPF_F2 / audioSettings.NYQUIST_FREQUENCY],'bandstop', analog=False, output='sos')
                                         [BSF_F1, BSF_F2], 'bandstop', analog=False,
                                         fs=SAMPLING_FREQUENCY, output='sos')
        # IMPORTANT: we need this TRICK to filter audio signal "in chunks" if required:
        zBandStop = np.zeros((sos_bandstop.shape[0], 2))
        sig3[:], zBandStop = signal.sosfilt(sos_bandstop, sig3[:], zi=zBandStop)
        logging.info("Applied band-stop filter on input signal, fstart = " + str(BSF_F1) + ", fstop = "+str(BSF_F2))

    # scale signal and normalize settings
    #####################################
    sig3_max = max(abs(sig3))
    if sig3_max == 0:
        logging.error("Error: sig3_max = 0")
        exit(cf.f_lineno)
    if SCALE_INPUT == True:
        sig3 = (sig3 / sig3_max)*MAX_VOLUME
        logging.info("Scaled input signal to max. = "+str(MAX_VOLUME))
    if NORMALIZE_SETTINGS == True:
        SKIP_CODING_IF_MIN_EXCEEDED = (SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT * sig3_max)
        logging.info("SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT = "+str(SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT)+" normalized to "+str(SKIP_CODING_IF_MIN_EXCEEDED))
        SKIP_CODING_IF_MAX_EXCEEDED = (SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT * sig3_max)
        logging.info("SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT = "+str(SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT)+" normalized to "+str(SKIP_CODING_IF_MAX_EXCEEDED))

    # Saturation?
    #############
    for i in range(len(sig3)):
        if sig3[i] > 1.0:
            logging.error("Error: saturation after scaling - irreparable situation, we may get stuck")
            logging.error("       SATURATION in sample i = " + str(i) + " with value = " + str(sig3[i]))
            exit(cf.f_lineno)

    # plot sig
    ##########
    if PLOT_SIG == True:
        plt.figure(1)
        plt.title("sig3 (input audio signal)")
        plt.plot(sig3)
        plt.ion()
        plt.show()
        plt.pause(.001)
        logging.info(">> Plotted sig3")

    # data for FFT
    ##############
    N = len(sig3)
    T = 1.0 / SAMPLING_FREQUENCY
    xf = np.fft.rfftfreq(N, d=T)

    # FFT of sig
    ############
    sig3f = rfft(sig3)
    sig3FFT = 2.0 / N * np.abs(sig3f[0:N // 2])
    xf = xf[:len(sig3FFT)]  # workaround: to match length of sig3FFT

    # plot FFT of sig
    #################
    if PLOT_FFT == True:
        plt.figure(2)
        plt.title("FFT of sig3")
        logging.info("Max sig3FFT = " + str(max(sig3FFT)))
        plt.plot(xf, sig3FFT, 'b', label='sig3FFT')
        plt.grid()
        plt.ion()
        plt.legend()
        plt.show()
        plt.pause(.001)
        logging.info(">> Plotted FFT of sig3")

    # NR_OF_CODE_FREQUENCIES_TO_CODE used for coding, for decoding NR_OF_CODE_FREQUENCIES is used.
    # NR_OF_CODE_FREQUENCIES_TO_CODE may be reduced if higher fc not codeable.
    ##############################################################################################
    NR_OF_CODE_FREQUENCIES_TO_CODE = NR_OF_CODE_FREQUENCIES

    # fill FFT-series
    #################
    NR_OF_CHUNKS = int(len(sig3) / CHUNK_LEN_SAMPLES)
    MAX_NR_OF_CODED_CHUNKS = int(NR_OF_CHUNKS / INTERLEAVED_CHUNKS)
    MAX_NR_OF_CODE_FREQUENCIES = int(NR_OF_CODE_FREQUENCIES_TO_CODE/INTERLEAVED_FC)
    logging.info("MAX_NR_OF_CODED_CHUNKS = "+str(MAX_NR_OF_CODED_CHUNKS))
    logging.info("MAX_NR_OF_CODE_FREQUENCIES = " + str(MAX_NR_OF_CODE_FREQUENCIES))
    code_sig3_chunk_FFT = [np.zeros(CHUNK_LEN_SAMPLES//2,dtype=complex)]*NR_OF_CHUNKS
    code_sig3_chunk_FFT_n = np.array([np.zeros(NR_OF_CODE_FREQUENCIES,dtype=complex)] * NR_OF_CHUNKS)
    code_sig3_chunk_FFT_n_mod = np.array([np.zeros(NR_OF_CODE_FREQUENCIES,dtype=complex)] * NR_OF_CHUNKS)
    for i in range(NR_OF_CHUNKS):
        code_sig3_part = sig3[i * CHUNK_LEN_SAMPLES:i * CHUNK_LEN_SAMPLES + CHUNK_LEN_SAMPLES]
        code_sig3_chunk_FFT[i] = rfft(code_sig3_part)
        for fcode in range(NR_OF_CODE_FREQUENCIES):
            code_sig3_chunk_FFT_n[i][fcode] = code_sig3_chunk_FFT[i][fcode+CODE_FREQUENCY_START_BIN]
            code_sig3_chunk_FFT_n_mod[i][fcode] = code_sig3_chunk_FFT[i][fcode+CODE_FREQUENCY_START_BIN]

    # plot FFT-series
    #################
    if PLOT_FFT == True:
        plt.figure(3)
        plt.title("sig3-FFT-series Real part of code frequencies")
        if CODE_WITH_MAGNITUDE == True:
            plt.plot(np.abs(code_sig3_chunk_FFT_n[:, :]))
        else:
            plt.plot(np.real(code_sig3_chunk_FFT_n[:,:]))
        plt.grid()
        plt.ion()
        plt.legend()
        plt.show()
        plt.pause(.001)
        logging.info("Plotted sig3-FFT-series (Re, Im) for code frequencies")

    # code message
    ##############
    global message_temp

    # check size of message
    LEN_ENCR_MSG_BITS = (LEN_MSG_BYTES*8//64)*64 + 64
    if(LEN_ENCR_MSG_BITS > MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES):
        logging.error("Error: message too large! msg_len_bits = "+str(LEN_ENCR_MSG_BITS)+", MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES = "+str(MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES))
        logging.error("       If close to complete, you may try a different password or configuration or just try again. Otherwise you need to select a different/bigger carrier file or reduce your messaage, e.g. split it.")
        if DO_PLOT == True:
            input("Press Enter to exit...")
        exit(cf.f_lineno)
    else:
        logging.info("In principle, the Message fits inside the carrier, msg_len_bits = " + str(LEN_ENCR_MSG_BITS) + " < MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES = " + str(MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES))

    # deception
    ###########
    # TODO: improve this, dont need to create such a long array
    deception = bitarray(int(NR_OF_CHUNKS)*NR_OF_CODE_FREQUENCIES)
    system_random.seed(SEED_IGNORE_CODE_DECEPTION)
    for i in range(len(deception)):
        deception[i] = system_random.randint(0, 1)

    # fill message with random bits
    # bits beyond message will be used as padding for deception
    ###########################################################
    message = copy.deepcopy(deception)
    message[:len(message_temp)] = message_temp

    # set bits to ignore in message
    # need repeatable/reproducible random numbers, therefore we cannot use SystemRandom()
    # random numbers are still "secure" because the seed is obtained from the password!
    # No need to handle Issue: [B311:blacklist] Standard pseudo-random generators are not
    #                   suitable for security/cryptographic purposes.
    #                   Severity: Low   Confidence: High
    ###########################################################
    ignore = bitarray(int(NR_OF_CHUNKS)*NR_OF_CODE_FREQUENCIES)
    ignore.setall(False)
    if DO_IGNORE_SOME:
        random.seed(SEED_IGNORE)
        for i in range(len(ignore)):
            # random values beyond threshold will be marked to be ignored
            if random.random() > IGNORE_THRESHOLD:
                ignore[i] = 1

    recode = bitarray(int(NR_OF_CHUNKS)*NR_OF_CODE_FREQUENCIES)
    # Note: initialize to zero, otherwise values may contain ones
    recode.setall(False)
    skip = bitarray(int(NR_OF_CHUNKS)*NR_OF_CODE_FREQUENCIES)
    skip.setall(False)
    skipForcePlus = bitarray(int(NR_OF_CHUNKS)*NR_OF_CODE_FREQUENCIES)
    skipForcePlus.setall(False)
    skipForceMinus = bitarray(int(NR_OF_CHUNKS)*NR_OF_CODE_FREQUENCIES)
    skipForceMinus.setall(False)
    nr_bit_errs = np.zeros(MAX_NR_OF_ITERATIONS)
    nr_bit_coded = np.zeros(MAX_NR_OF_ITERATIONS)
    nr_bit_decoded = np.zeros(MAX_NR_OF_ITERATIONS)
    nr_bit_coded_fc = np.array([np.zeros(NR_OF_CODE_FREQUENCIES)] * MAX_NR_OF_ITERATIONS)
    nr_bit_decoded_fc = np.array([np.zeros(NR_OF_CODE_FREQUENCIES)] * MAX_NR_OF_ITERATIONS)
    code_sig3_chunk_FFT_org = copy.deepcopy(code_sig3_chunk_FFT)
    code_sig3_chunk_FFT_n_org = copy.deepcopy(code_sig3_chunk_FFT_n)
    code_sig3_chunk_FFT_n_mod_org = copy.deepcopy(code_sig3_chunk_FFT_n_mod)

    # initialization for progress bar
    #################################
    items = list(range(0, LEN_ENCR_MSG_BITS))
    total_items = len(items)
    print_progress(0, total_items, prefix='Progress:', suffix='Complete', bar_length=50)

    ###########################################################
    ###########################################################
    #
    # main loop
    #
    # if readback after coding fails, then we try again..
    ###########################################################
    ###########################################################
    for curr_iteration in range(1, MAX_NR_OF_ITERATIONS + 1):
        # help variables to shorten loops
        #################################
        if INTERPOLATE_AND_DUMMY_CODE_ALL == False:
            i_max = NR_OF_CHUNKS
            fc_max = NR_OF_CODE_FREQUENCIES

        # have still enough bits?
        #########################
        total_ignore = ignore.count(1)
        total_skip = skip.count(1)
        total_skip_old = 0
        total_ignore_and_skip = total_ignore + total_skip
        logging.info("total_ignore = " + str(total_ignore))
        logging.info("total_skip = "+str(total_skip))
        logging.info("total_ignore_and_skip = " + str(total_ignore_and_skip))
        remaining_nr_of_coding_bits = MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES - total_ignore_and_skip
        if (LEN_ENCR_MSG_BITS > remaining_nr_of_coding_bits):
            logging.error("Error: message too large! msg_len_bits = " + str(LEN_ENCR_MSG_BITS) + ", remaining_nr_of_coding_bits = " + str(remaining_nr_of_coding_bits)+" found in iteration "+str(curr_iteration))
            logging.error("       If close to complete, you may try a different password or configuration or just try again. Otherwise you need to select a different/bigger carrier file or reduce your messaage, e.g. split it.")
            exit(cf.f_lineno)
        else:
            logging.info("The Message still fits inside the carrier, msg_len_bits = " + str(LEN_ENCR_MSG_BITS) + " < remaining_nr_of_coding_bits = " + str(remaining_nr_of_coding_bits)+" in iteration "+str(curr_iteration))

        # DO_LAST ?
        # use "if DO_LAST == Fasle:" so we dont CODE again in case we already obtained a good CODE without errors
        # or use "if True:" to code again just to show the corresponding plots in the last iteration
        ############################################################################################
        if True: # DO_LAST == False:
            # clear in each iteration
            sig3_recovered_mod = copy.deepcopy(sig3)
            code_sig3_chunk_FFT = copy.deepcopy(code_sig3_chunk_FFT_org)
            code_sig3_chunk_FFT_n = copy.deepcopy(code_sig3_chunk_FFT_n_org)
            code_sig3_chunk_FFT_n_mod = copy.deepcopy(code_sig3_chunk_FFT_n_mod_org)
            nrOfBitsCodedInMsg = 0

            # flag to leave loops
            leave_loops = False

            # loop CHUNKS
            #############
            for i in range(INTERLEAVED_CHUNKS, NR_OF_CHUNKS - 1):
                # leave loop?
                if leave_loops == True:
                    break

                # code alternating samples of FFT-series
                ########################################
                if i % INTERLEAVED_CHUNKS == 0:

                    # loop FCs
                    ##########
                    for fc in range(0, NR_OF_CODE_FREQUENCIES_TO_CODE, INTERLEAVED_FC):
                        # leave loop?
                        if leave_loops == True:
                            break

                        # leave code loops?
                        ###################
                        if INTERPOLATE_AND_DUMMY_CODE_ALL == False and (nrOfBitsCodedInMsg > LEN_ENCR_MSG_BITS):
                            # dont need to code anything else, real message already coded and
                            # dont want to code dummies
                            ###########################
                            i_max = i
                            fc_max = fc
                            leave_loops = True
                            break

                        # code magnitude or only .real part?
                        ####################################
                        if CODE_WITH_MAGNITUDE == True:
                            if AVG_INTERPOLATION == True:
                                plus = np.array([code_sig3_chunk_FFT[i + 1][fc + CODE_FREQUENCY_START_BIN],
                                                 code_sig3_chunk_FFT[i + 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                                 code_sig3_chunk_FFT[i + 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                                if INTERPOLATE_WITH_MEAN == True:
                                    avg_plus = np.mean(plus)
                                else:
                                    avg_plus = np.median(plus)
                                minus = np.array([code_sig3_chunk_FFT[i - 1][fc + CODE_FREQUENCY_START_BIN],
                                                  code_sig3_chunk_FFT[i - 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                                  code_sig3_chunk_FFT[i - 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                                if INTERPOLATE_WITH_MEAN == True:
                                    avg_minus = np.mean(minus)
                                else:
                                    avg_minus = np.median(minus)
                                diffFFT_n_real = np.real(avg_plus - avg_minus)
                            else:
                                diffFFT_n_real = np.real(
                                    code_sig3_chunk_FFT_n[i + 1, fc] - code_sig3_chunk_FFT_n[i - 1, fc])
                            interpolatedFFTn_real = abs(
                                code_sig3_chunk_FFT_n[i - 1, fc].real + diffFFT_n_real / 2.0) * np.sign(
                                code_sig3_chunk_FFT_n[i, fc].real)
                            # and now .imag part
                            ####################
                            if AVG_INTERPOLATION == True:
                                diffFFT_n_imag = np.imag(avg_plus - avg_minus)
                            else:
                                diffFFT_n_imag = np.imag(
                                    code_sig3_chunk_FFT_n[i + 1, fc] - code_sig3_chunk_FFT_n[i - 1, fc])
                            interpolatedFFTn_imag = abs(
                                code_sig3_chunk_FFT_n[i - 1, fc].imag + diffFFT_n_imag / 2.0) * np.sign(
                                code_sig3_chunk_FFT_n[i, fc].imag)
                        # code only .real part
                        ######################
                        else:
                            if AVG_INTERPOLATION == True:
                                plus = np.array([code_sig3_chunk_FFT[i + 1][fc + CODE_FREQUENCY_START_BIN],
                                                 code_sig3_chunk_FFT[i + 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                                 code_sig3_chunk_FFT[i + 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                                if INTERPOLATE_WITH_MEAN == True:
                                    avg_plus = np.mean(plus)
                                else:
                                    avg_plus = np.median(plus)
                                minus = np.array([code_sig3_chunk_FFT[i - 1][fc + CODE_FREQUENCY_START_BIN],
                                                  code_sig3_chunk_FFT[i - 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                                  code_sig3_chunk_FFT[i - 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                                if INTERPOLATE_WITH_MEAN == True:
                                    avg_minus = np.mean(minus)
                                else:
                                    avg_minus = np.median(minus)
                                diffFFT_n = np.real(avg_plus - avg_minus)
                            else:
                                diffFFT_n = np.real(code_sig3_chunk_FFT_n[i + 1, fc] - code_sig3_chunk_FFT_n[i - 1, fc])
                            interpolatedFFTn = abs(code_sig3_chunk_FFT_n[i - 1, fc].real + diffFFT_n / 2.0) * np.sign(
                                code_sig3_chunk_FFT_n[i, fc].real)

                        # ignore bit in "message"?
                        ##########################
                        if ignore[i + fc*NR_OF_CHUNKS] == False:
                            # flag to code or skip
                            DO_CODE = False

                            # code magnitude or only .real part?
                            ####################################
                            if CODE_WITH_MAGNITUDE == True:
                                check_real = SKIP_CODING_IF_MIN_EXCEEDED < abs(interpolatedFFTn_real * INTERPOLATION_FACTOR_PERCENT_MINUS) and \
                                             abs(interpolatedFFTn_real * INTERPOLATION_FACTOR_PERCENT_PLUS) < SKIP_CODING_IF_MAX_EXCEEDED
                                # also check on imaginary part?
                                ###############################
                                if CHECK_IMAG_TOO:
                                    check_imag = SKIP_CODING_IF_MIN_EXCEEDED < abs(interpolatedFFTn_imag * INTERPOLATION_FACTOR_PERCENT_MINUS) and \
                                                 abs(interpolatedFFTn_imag * INTERPOLATION_FACTOR_PERCENT_PLUS) < SKIP_CODING_IF_MAX_EXCEEDED
                                else:
                                    check_imag = True
                                ######################################################################################################
                                # IMPORTANT:
                                # In the following check we use "OR" in the hope we can code more chunks which then pass decoding too.
                                # Using "AND" leads to much worse results!
                                ######################################################################################################
                                check = check_real or check_imag
                            else:
                                check = SKIP_CODING_IF_MIN_EXCEEDED < abs(interpolatedFFTn * INTERPOLATION_FACTOR_PERCENT_MINUS) and \
                                        abs(interpolatedFFTn * INTERPOLATION_FACTOR_PERCENT_PLUS) < SKIP_CODING_IF_MAX_EXCEEDED

                            # skip values which were marked in readback to be skipped
                            #########################################################
                            if skip[i + fc*NR_OF_CHUNKS]==False:
                                # skip values that are too low in absolute value
                                ################################################
                                if check:
                                    DO_CODE = True
                                else:
                                    if CODE_WITH_MAGNITUDE == True:
                                        logging.debug("SKIP interpolation real point(" + str(i) + ") = " + str(interpolatedFFTn_real) + "due to EXCEEDED RElATIVE CODING_DELTA for fc = "+str(fc))
                                        logging.debug("SKIP interpolation imag point(" + str(i) + ") = " + str(interpolatedFFTn_imag) + "due to EXCEEDED RElATIVE CODING_DELTA for fc = " + str(fc))
                                    else:
                                        logging.debug("SKIP interpolation point(" + str(i) + ") = " + str(interpolatedFFTn) + "due to EXCEEDED RElATIVE CODING_DELTA for fc = "+str(fc))
                            else:
                                if CODE_WITH_MAGNITUDE == True:
                                    logging.debug("SKIP interpolation real point(" + str(i) + ") = " + str(interpolatedFFTn_real) + "due to SKIP set in previous readback..for fc = "+str(fc))
                                    logging.debug("SKIP interpolation imag point(" + str(i) + ") = " + str(interpolatedFFTn_imag) + "due to SKIP set in previous readback..for fc = " + str(fc))
                                else:
                                    logging.debug("SKIP interpolation point(" + str(i) + ") = " + str(interpolatedFFTn) + "due to SKIP set in previous readback..for fc = "+str(fc))

                            # code CODE_FACTOR_PLUS / MINUS of interpolated signal
                            ######################################################
                            if (DO_CODE == True) and ((INTERPOLATE_AND_DUMMY_CODE_ALL==True) or (nrOfBitsCodedInMsg < LEN_ENCR_MSG_BITS)):
                                # need recode ?
                                ###############
                                if recode[i + fc * NR_OF_CHUNKS] == True:
                                    CODE_FACTOR_PERCENT_PLUS = CODE_FACTOR_PERCENT_PLUS*RECODE_FACTOR_PLUS
                                    CODE_FACTOR_PERCENT_MINUS = CODE_FACTOR_PERCENT_MINUS*RECODE_FACTOR_MINUS

                                # CODE ONE?
                                ###########
                                if message[nrOfBitsCodedInMsg] == 1:
                                    if CODE_WITH_MAGNITUDE == True:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn_real * CODE_FACTOR_PERCENT_MINUS + 1j * interpolatedFFTn_imag * CODE_FACTOR_PERCENT_MINUS
                                    else:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn * CODE_FACTOR_PERCENT_MINUS + 1j * 0.0
                                # CODE ZERO
                                ###########
                                else:
                                    if CODE_WITH_MAGNITUDE == True:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn_real * CODE_FACTOR_PERCENT_PLUS + 1j * interpolatedFFTn_imag * CODE_FACTOR_PERCENT_PLUS
                                    else:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn * CODE_FACTOR_PERCENT_PLUS + 1j * 0.0

                                # increment counter of coded bits..
                                ###################################
                                nrOfBitsCodedInMsg = nrOfBitsCodedInMsg + 1
                                nr_bit_coded_fc[curr_iteration,fc] = nr_bit_coded_fc[curr_iteration,fc] + 1

                                # restore default values in case of recode
                                ##########################################
                                if recode[i + fc * NR_OF_CHUNKS] == True:
                                    CODE_FACTOR_PERCENT_PLUS = CODE_FACTOR_PERCENT_PLUS_OLD
                                    CODE_FACTOR_PERCENT_MINUS = CODE_FACTOR_PERCENT_MINUS_OLD
                            # DO NOT CODE, but need interpolation
                            #####################################
                            else:
                                # brute-force skip PLUS?
                                # note: multiplying with (CODE_FACTOR_PERCENT_PLUS*3) does NOT REVERT the sign, i.e. it remains on the same side (above or below zero)
                                ######################################################################################################################################
                                if skipForcePlus[i + fc*NR_OF_CHUNKS] == True:
                                    if CODE_WITH_MAGNITUDE == True:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn_real * (CODE_FACTOR_PERCENT_PLUS*3.0) + 1j * interpolatedFFTn_imag * (CODE_FACTOR_PERCENT_PLUS*3.0)
                                    else:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn * (CODE_FACTOR_PERCENT_PLUS*3.0) + 1j * 0.0
                                # brute-force skip MINUS? - last chance!
                                ########################################
                                elif skipForceMinus[i + fc*NR_OF_CHUNKS] == True:
                                    if CODE_WITH_MAGNITUDE == True:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn_real * (CODE_FACTOR_PERCENT_MINUS*3.0) + 1j * interpolatedFFTn_imag * (CODE_FACTOR_PERCENT_MINUS*3.0)
                                    else:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn * (CODE_FACTOR_PERCENT_MINUS*3.0) + 1j * 0.0
                                # just linearize and skip?
                                ##########################
                                elif (INTERPOLATE_AND_DUMMY_CODE_ALL == True) or (nrOfBitsCodedInMsg < LEN_ENCR_MSG_BITS):
                                    # LINEAR INTERPOLATION of interleaved samples of FFT-series
                                    ###########################################################
                                    if CODE_WITH_MAGNITUDE == True:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn_real + 1j * interpolatedFFTn_imag
                                    else:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn + 1j * 0.0
                                    # and mark as skipped
                                    #####################
                                    skip[i + fc * NR_OF_CHUNKS] = True

                            # set code_sig3_chunk_FFT_n_mod[i][fc]
                            # and inverse FFT to obtain coded audio chunk (in time domain = sample space)
                            #############################################################################
                            code_sig3_chunk_FFT_n_mod[i][fc] = code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN+fc]
                            sig3_recovered_part = irfft(code_sig3_chunk_FFT[i],n=CHUNK_LEN_SAMPLES)
                            sig3_recovered_mod[i * CHUNK_LEN_SAMPLES:i * CHUNK_LEN_SAMPLES + CHUNK_LEN_SAMPLES] = sig3_recovered_part
                        # ignore bit
                        ############
                        else:
                            if DO_DECEPTION == True:
                                # we ignore bit but code it anyways for deception of attacker
                                #############################################################
                                r = deception[i + fc*NR_OF_CHUNKS] # same deception with every iteration
                                if r == 1:
                                    if CODE_WITH_MAGNITUDE == True:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn_real * CODE_FACTOR_PERCENT_MINUS + 1j * interpolatedFFTn_imag * CODE_FACTOR_PERCENT_MINUS
                                    else:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn * CODE_FACTOR_PERCENT_MINUS + 1j * 0.0
                                else:
                                    if CODE_WITH_MAGNITUDE == True:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn_real * CODE_FACTOR_PERCENT_PLUS + 1j * interpolatedFFTn_imag * CODE_FACTOR_PERCENT_PLUS
                                    else:
                                        code_sig3_chunk_FFT[i][CODE_FREQUENCY_START_BIN + fc] = interpolatedFFTn * CODE_FACTOR_PERCENT_PLUS + 1j * 0.0
                                logging.debug("Ignoring bit of message at position "+str(i+fc*NR_OF_CHUNKS)+", deception with "+str(r))
                            else:
                                logging.debug("Ignoring bit of message at position "+str(i+fc*NR_OF_CHUNKS)+", no deception done")

            # message written
            #################
            logging.info("Written message of length nrOfBitsCodedInMsg = "+str(nrOfBitsCodedInMsg))
            logging.info("LEN_ENCR_MSG_BITS = " + str(LEN_ENCR_MSG_BITS))

            # Saturation?
            #############
            # TODO: remove this old assertion, not needed anymore..(?)
            for i in range(len(sig3_recovered_mod)):
                if sig3_recovered_mod[i] > 1.0:
                    logging.error("Error: saturation after coding - irreparable situation, we may get stuck")
                    logging.error("       SATURATION in sample i = " + str(i) + " with value = " + str(sig3_recovered_mod[i]))
                    exit(cf.f_lineno)

            # Error of coding
            #################
            err3_recovered_mod = sig3_recovered_mod - sig3
            if CODE_WITH_MAGNITUDE == True:
                err_sig3_chunk_FFT_n_mod = np.abs(code_sig3_chunk_FFT_n_mod) - np.abs(code_sig3_chunk_FFT_n)
            else:
                err_sig3_chunk_FFT_n_mod = np.real(code_sig3_chunk_FFT_n_mod) - np.real(code_sig3_chunk_FFT_n)

            # plot err3_recovered_mod
            #########################
            if DO_LAST and PLOT_ERR == True:
                plt.figure(4)
                plt.title("err3_recovered_mod")
                plt.plot(err3_recovered_mod)
                plt.ion()
                plt.show()
                plt.pause(.001)
                logging.info("Plotted err3_recovered_mod")

            # plot sig3_recovered_mod and err3_recovered_mod
            ################################################
            if DO_LAST and PLOT_ERR == True:
                plt.figure(5)
                plt.title("sig3, sig3_recovered_mod and err3_recovered_mod")
                plt.plot(sig3)
                plt.plot(sig3_recovered_mod)
                plt.plot(err3_recovered_mod)
                plt.ion()
                plt.show()
                plt.pause(.001)
                logging.info("Plotted sig3, sig3_recovered_mod and err3_recovered_mod")

            # plot code_sig3_chunk_FFT_n and code_sig3_chunk_FFT_n_mod
            ##########################################################
            if DO_LAST and PLOT_FFT == True:
                plt.figure(6)
                plt.title("code_sig3_chunk_FFT_n, code_sig3_chunk_FFT_n_mod and err_sig3_chunk_FFT_n_mod")
                if CODE_WITH_MAGNITUDE == True:
                    plt.plot(np.abs(code_sig3_chunk_FFT_n[:,:]))
                    plt.plot(np.abs(code_sig3_chunk_FFT_n_mod[:,:]))
                else:
                    plt.plot(np.real(code_sig3_chunk_FFT_n[:,:]))
                    plt.plot(np.real(code_sig3_chunk_FFT_n_mod[:,:]))
                plt.plot(err_sig3_chunk_FFT_n_mod[:,:])
                plt.ion()
                plt.show()
                plt.pause(.001)
                logging.info("Plotted code_sig3_chunk_FFT_n, code_sig3_chunk_FFT_n_mod and err_sig3_chunk_FFT_n_mod")

            # plot 3D
            #########
            if DO_LAST and PLOT_3D:
                fig = plt.figure(7654)
                ax = fig.add_subplot(projection='3d')
                yticks = np.arange(20)
                u = 0
                for kk in range(80):
                    xs = np.arange(80)
                    ys = np.abs(code_sig3_chunk_FFT_n_mod[0:80, u])
                    u = u + 1
                    ax.bar(xs, ys, zs=kk, zdir='y', color='b', alpha=0.8)
                ax.set_xlabel('X')
                ax.set_ylabel('Y')
                ax.set_zlabel('Z')
                ax.set_yticks(yticks)
                plt.show()

        # Convert sig3 to audio as 16-bit data
        ######################################
        # Note: subtract "1" to MAX_AMPLITUDE, if we used instead MAX_AMPLITUDE we would flip the sign at limit values!
        audio3_recovered_mod = sig3_recovered_mod * (MAX_AMPLITUDE - 1)
        audio3_recovered_mod = audio3_recovered_mod.astype(np.int16)
        logging.info("Converted audio3_recovered_mod to np.int16")

        # store audio (buffered signal) as _mod.wav (contains at least:
        # rounding errors due to formatting: error approx. 1bit (0.003%).
        # lineariation errors (biggest errors!): XXX bit
        # coding errors: XXX bit
        #################################################################
        wf.write(FILE_NAME + "_mod.wav", SAMPLING_FREQUENCY, audio3_recovered_mod)
        logging.info("Written " + FILE_NAME + "_mod.wav from audio")

        # _mod.wav -> _out.mp3
        # _out.mp3 is the .mp3 "SCALED" version of the carrier file, now containing the stego-message
        #############################################################################################
        command = "ffmpeg -loglevel quiet -y -i " + FILE_NAME + "_mod.wav -ab " + MP3_BITRATE_STR + " -sample_fmt "+MP3_SAMPLE_FORMAT+" -metadata comment='comment' " + FILE_NAME + "_out.mp3"
        p1 = subprocess.Popen(shlex.split(command), shell=False, stdout=subprocess.PIPE)
        out, err = p1.communicate()
        if p1.returncode == 0:
            pass
        else:
            logging.error("Error: could not run ffmpeg!")
            exit(cf.f_lineno)
        p1.terminate()
        p1.kill()
        logging.info("Converted " + FILE_NAME + "_mod.wav to " + FILE_NAME + "_out.mp3")

        # convert _out.mp3 to _out.wav to make it readable by code (readback)
        #####################################################################
        command = "ffmpeg -loglevel quiet -y -i " + FILE_NAME + "_out.mp3 -vn -acodec "+WAV_SAMPLE_FORMAT+" -ac 1 -ar " + str(
            SAMPLING_FREQUENCY) + " -f wav " + FILE_NAME + "_out.wav"
        p1 = subprocess.Popen(shlex.split(command), shell=False, stdout=subprocess.PIPE)
        out, err = p1.communicate()
        if p1.returncode == 0:
            pass
        else:
            logging.error("Error: could not run ffmpeg!")
            exit(cf.f_lineno)
        p1.terminate()
        p1.kill()
        logging.info("Converted " + FILE_NAME + "_out.mp3 to " + FILE_NAME + "_out.wav")

        # readback temporary stego file
        # read sig4 <- _out.wav  (with _out.wav <- _out.mp3 <- sig3_recovered_mod)
        ##########################################################################
        sig4, samplerate = sf.read(FILE_NAME + "_out.wav")
        logging.info("Read " + FILE_NAME + "_out.wav as sig4")

        # copy _out.mp3 -> OUT_FILE_NAME
        # and delete temporary files
        ################################
        if DO_LAST == True:
            # Note: if you dont want to copy metadata and permissions use instead:
            #            copyfile(FILE_NAME+"_out.mp3", OUT_FILE_NAME)
            ##########################################################
            copy2(FILE_NAME + "_out.mp3", OUT_FILE_NAME)
            # hide output file
            ##################
            if HIDE == True:
                # TODO: correct Issue: [B607:start_process_with_partial_path]
                # Issue: [B607:start_process_with_partial_path] Starting a process with a partial executable path
                # Severity: Low   Confidence: High
                ##################################
                subprocess.check_call(["attrib","+h",OUT_FILE_NAME])
                logging.info("Hidden " + OUT_FILE_NAME)
            # delete temporary files
            ########################
            if KEEP_TEMP_FILES == False:
                # del in.wav
                ############
                if os.path.exists(FILE_NAME + ".wav"):
                    os.remove(FILE_NAME + ".wav")
                    logging.info("Deleted " + FILE_NAME + ".wav")
                # del in_mod.wav
                ################
                if os.path.exists(FILE_NAME + "_mod.wav"):
                    os.remove(FILE_NAME + "_mod.wav")
                    logging.info("Deleted " + FILE_NAME + "_mod.wav")
                # del in_out.wav
                ################
                if os.path.exists(FILE_NAME + "_out.wav"):
                    os.remove(FILE_NAME + "_out.wav")
                    logging.info("Deleted " + FILE_NAME + "_out.wav")
                # del in_out.mp3
                ################
                if os.path.exists(FILE_NAME + "_out.mp3"):
                    os.remove(FILE_NAME + "_out.mp3")
                    logging.info("Deleted " + FILE_NAME + "_out.mp3")

            # play audio3_recovered_mod (buffered signal)
            #############################################
            if PLAY_ON == True:
                logging.info("Playing stego file (= carrier + message)..")
                # Start playback
                play_obj = sa.play_buffer(audio3_recovered_mod, NUM_CHANNELS, BYTES_PER_SAMPLE, SAMPLING_FREQUENCY)
                # Wait for playback to finish before exiting
                play_obj.wait_done()
                logging.info("Finished playing stego file")

        # Due to format change .wav -> .mp3 and back to .wav we may have now a different length.
        # So we need to shorten the signal.
        # TODO: remove this old assertion and workaround, not needed anymore..(?)
        #######################################################################################
        if len(sig3) != len(sig4):
            logging.info("Warning: len_sig3("+str(len(sig3))+") != len_sig4("+str(len(sig4))+")..lenghts will be corrected")
            sig4 = sig4[:len(sig3)]

        # NORMALIZE Settings
        ####################
        if NORMALIZE_SETTINGS == True:
            sig4_max = max(abs(sig4))
            if sig4_max == 0:
                logging.error("Error: sig4_max = 0")
                exit(cf.f_lineno)
            SKIP_CODING_IF_MIN_EXCEEDED = (SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT * sig4_max)
            logging.info("SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT = " + str(SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT) + " normalized to " + str(SKIP_CODING_IF_MIN_EXCEEDED))
            SKIP_CODING_IF_MAX_EXCEEDED = (SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT * sig4_max)
            logging.info("SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT = " + str(SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT) + " normalized to " + str(SKIP_CODING_IF_MAX_EXCEEDED))

        # error between audio signals (modified - original)
        ###################################################
        err4 = sig4 - sig3
        err4_percent = err4 * 100.0
        err4_percent_max = max(err4_percent)
        logging.info("err4_percent_max = " + str(err4_percent_max))

        # generate err.wav
        ##################
        if KEEP_TEMP_FILES == True:
            err4_np = (err4 * MAX_AMPLITUDE)
            err4_np = err4_np.astype(np.int16)
            logging.info("Converted err4 to err4_np (format np.int16)")
            wf.write(FILE_NAME + "_err.wav", SAMPLING_FREQUENCY, err4_np)
            logging.info("Written " + FILE_NAME + "_err.wav")

        # PSNR, SNR
        ###########
        sig3_np = sig3.astype(np.float64) * float(MAX_AMPLITUDE)
        sig4_np = sig4.astype(np.float64) * float(MAX_AMPLITUDE)
        psnrErr4 = psnr(sig3_np, sig4_np, MAX_AMPLITUDE)
        snrErr4 = snr(sig3_np, sig4_np)
        logging.info("psnrErr4 = " + str(psnrErr4))
        logging.info("snrErr4 = " + str(snrErr4))

        # plot err4 = sig4 - sig3
        ########################
        if DO_LAST and PLOT_ERR == True:
            plt.figure(7)
            plt.title("err4[%] = sig4 - sig3 @" + MP3_BITRATE_STR + "(err4_max = " + "{:.2f}".format(
                err4_percent_max) + ",\n PSNR = " + "{:.2f}".format(psnrErr4) + "dB,\n SNR = " + "{:.2f}".format(
                snrErr4) + "dB)")
            plt.plot(err4_percent)
            plt.ion()
            plt.show()
            plt.pause(.001)
            logging.info("Plotted err4[%]")

        # fill FFT-series
        #################
        code_sig4_chunk_FFT = [np.zeros(CHUNK_LEN_SAMPLES//2, dtype=complex)] * NR_OF_CHUNKS
        code_sig4_chunk_FFT_n = np.array([np.zeros(NR_OF_CODE_FREQUENCIES, dtype=complex)] * NR_OF_CHUNKS)
        for i in range(NR_OF_CHUNKS):
            code_sig4_part = sig4[i * CHUNK_LEN_SAMPLES:i * CHUNK_LEN_SAMPLES + CHUNK_LEN_SAMPLES]
            code_sig4_chunk_FFT[i] = rfft(code_sig4_part)
            for fcode in range(NR_OF_CODE_FREQUENCIES):
                code_sig4_chunk_FFT_n[i][fcode] = code_sig4_chunk_FFT[i][fcode+CODE_FREQUENCY_START_BIN]

        # sorted signals
        ################
        sig3_sorted = np.sort(sig3)
        sig4_sorted = np.sort(sig4)
        err_between_sig3_sorted_and_sig4_sorted = sig4_sorted - sig3_sorted

        # plot sorted sig3 and sig4 and the error between them
        ######################################################
        if DO_LAST and PLOT_CDF == True:
            plt.figure(8)
            plt.title("sig3_sorted, sig4_sorted and err_between_sig3_sorted_and_sig4_sorted")
            plt.plot(sig3_sorted, 'b', label='sig3_sorted')
            plt.plot(sig4_sorted, 'r', label='sig4_sorted')
            plt.plot(err_between_sig3_sorted_and_sig4_sorted, 'g', label='err_between_sig3_sorted_and_sig4_sorted')
            plt.grid()
            plt.ion()
            plt.legend()
            plt.show()
            plt.pause(.001)
            logging.info("Plotted sig3_sorted, sig4_sorted and err_between_sig3_sorted_and_sig4_sorted")

        # count errors when decoding
        ############################
        nrOfMsgErr = 0

        # ignore bits in message
        # generate random bits AGAIN as if we read this file for the first time...
        # NOTE: we need reproducible/repeatable random numbers, therefore we cannot use SystemRandom()
        #       random numbers are still secure because the seed is obtained from the password!
        #######################################################################################
        ignore2 = bitarray(int(NR_OF_CHUNKS)*NR_OF_CODE_FREQUENCIES)
        ignore2.setall(False)
        if DO_IGNORE_SOME:
            random.seed(SEED_IGNORE)
            for i in range(len(ignore2)):
                if random.random() > IGNORE_THRESHOLD:
                    ignore2[i] = 1

        # DECODE readback signal
        # (use as a reference "own" interpolated value) - previous signals/data are not supposed to be known
        # TODO: optimization: first decode only header-bits, then if header ok decode rest bits
        #######################################################################################
        err_sig4_chunk_FFT_absolute = np.array([np.zeros(NR_OF_CODE_FREQUENCIES)] * NR_OF_CHUNKS)
        err_sig4_chunk_FFT_percent = np.array([np.zeros(NR_OF_CODE_FREQUENCIES)] * NR_OF_CHUNKS)

        # flag to leave loops
        leave_loops = False

        # loop chunks
        #############
        for i in range(INTERLEAVED_CHUNKS, NR_OF_CHUNKS - 1):
            # leave loop?
            if leave_loops == True:
                break

            # decode alternating samples of FFT-series
            ##########################################
            if i % INTERLEAVED_CHUNKS == 0:

                # loop coding frequencies
                #########################
                for fc in range(0, NR_OF_CODE_FREQUENCIES_TO_CODE, INTERLEAVED_FC):
                    # leave loop?
                    if leave_loops == True:
                        break

                    # leave decode loops?
                    #####################
                    if INTERPOLATE_AND_DUMMY_CODE_ALL == False and (i == i_max and fc == fc_max):
                        leave_loops = True
                        break

                    # ignore bit in message?
                    ########################
                    if ignore2[i + fc*NR_OF_CHUNKS] == False:
                        # was message coded with magnitude or only .real part?
                        ######################################################
                        if CODE_WITH_MAGNITUDE == True:
                            if AVG_INTERPOLATION == True:
                                plus = np.array([code_sig4_chunk_FFT[i + 1][fc + CODE_FREQUENCY_START_BIN],
                                                 code_sig4_chunk_FFT[i + 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                                 code_sig4_chunk_FFT[i + 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                                if INTERPOLATE_WITH_MEAN == True:
                                    avg_plus = np.mean(plus)
                                else:
                                    avg_plus = np.median(plus)
                                minus = np.array([code_sig4_chunk_FFT[i - 1][fc + CODE_FREQUENCY_START_BIN],
                                                  code_sig4_chunk_FFT[i - 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                                  code_sig4_chunk_FFT[i - 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                                if INTERPOLATE_WITH_MEAN == True:
                                    avg_minus = np.mean(minus)
                                else:
                                    avg_minus = np.median(minus)
                                diffFFT_n_real = np.real(avg_plus - avg_minus)
                            else:
                                diffFFT_n_real = np.real(code_sig4_chunk_FFT_n[i + 1, fc]) - np.real(code_sig4_chunk_FFT_n[i - 1, fc])
                            interpolatedFFTn_real = abs(code_sig4_chunk_FFT_n[i - 1, fc].real + diffFFT_n_real / 2.0) * np.sign(code_sig4_chunk_FFT_n[i, fc].real)
                            if AVG_INTERPOLATION == True:
                                diffFFT_n_imag = np.imag(avg_plus - avg_minus)
                            else:
                                diffFFT_n_imag = np.imag(code_sig4_chunk_FFT_n[i + 1, fc]) - np.imag(code_sig4_chunk_FFT_n[i - 1, fc])
                            interpolatedFFTn_imag = abs(code_sig4_chunk_FFT_n[i - 1, fc].imag + diffFFT_n_imag / 2.0) * np.sign(code_sig4_chunk_FFT_n[i, fc].imag)
                        # only .real part coded
                        #######################
                        else:
                            if AVG_INTERPOLATION == True:
                                plus = np.array([code_sig4_chunk_FFT[i + 1][fc + CODE_FREQUENCY_START_BIN],
                                                 code_sig4_chunk_FFT[i + 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                                 code_sig4_chunk_FFT[i + 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                                if INTERPOLATE_WITH_MEAN == True:
                                    avg_plus = np.mean(plus)
                                else:
                                    avg_plus = np.median(plus)
                                minus = np.array([code_sig4_chunk_FFT[i - 1][fc + CODE_FREQUENCY_START_BIN],
                                                  code_sig4_chunk_FFT[i - 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                                  code_sig4_chunk_FFT[i - 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                                if INTERPOLATE_WITH_MEAN == True:
                                    avg_minus = np.mean(minus)
                                else:
                                    avg_minus = np.median(minus)
                                diffFFT_n = np.real(avg_plus - avg_minus)
                            else:
                                diffFFT_n = np.real(code_sig4_chunk_FFT_n[i + 1,fc] - code_sig4_chunk_FFT_n[i - 1,fc])
                            ############################################################
                            interpolatedFFTn = abs(code_sig4_chunk_FFT_n[i - 1, fc].real + diffFFT_n / 2.0) * np.sign(code_sig4_chunk_FFT_n[i, fc].real)

                        # flags for plausibility checks
                        ###############################
                        check_real = False
                        check_imag = False

                        # was message coded with magnitude or only .real part?
                        ######################################################
                        if CODE_WITH_MAGNITUDE == True:
                            check_real = SKIP_CODING_IF_MIN_EXCEEDED < abs(interpolatedFFTn_real * INTERPOLATION_FACTOR_PERCENT_MINUS) and \
                                         abs(interpolatedFFTn_real * INTERPOLATION_FACTOR_PERCENT_PLUS) < SKIP_CODING_IF_MAX_EXCEEDED
                            if CHECK_IMAG_TOO:
                                check_imag = SKIP_CODING_IF_MIN_EXCEEDED < abs(interpolatedFFTn_imag * INTERPOLATION_FACTOR_PERCENT_MINUS) and \
                                             abs(interpolatedFFTn_imag * INTERPOLATION_FACTOR_PERCENT_PLUS) < SKIP_CODING_IF_MAX_EXCEEDED
                            else:
                                check_imag = True
                            check = check_real and check_imag
                        # only .real part coded
                        #######################
                        else:
                            check = SKIP_CODING_IF_MIN_EXCEEDED < abs(interpolatedFFTn * INTERPOLATION_FACTOR_PERCENT_MINUS) and \
                                    abs(interpolatedFFTn * INTERPOLATION_FACTOR_PERCENT_PLUS) < SKIP_CODING_IF_MAX_EXCEEDED
                        # interpolated value in coding range?
                        #####################################
                        if check:
                            check1_real = False
                            check1_imag = False
                            if CODE_WITH_MAGNITUDE == True:
                                check1_real = SKIP_CODING_IF_MIN_EXCEEDED < abs(code_sig4_chunk_FFT_n[i, fc].real) < SKIP_CODING_IF_MAX_EXCEEDED
                                if CHECK_IMAG_TOO:
                                    check1_imag = SKIP_CODING_IF_MIN_EXCEEDED < abs(code_sig4_chunk_FFT_n[i, fc].imag) < SKIP_CODING_IF_MAX_EXCEEDED
                                else:
                                    check1_imag = True
                                check1 = (check1_real and check_real) or (check1_imag and check_imag)
                            else:
                                check1 = SKIP_CODING_IF_MIN_EXCEEDED < abs(code_sig4_chunk_FFT_n[i,fc].real) < SKIP_CODING_IF_MAX_EXCEEDED
                            # actual sample in coding range?
                            ################################
                            if check1:
                                check2_real = False
                                if CODE_WITH_MAGNITUDE == True:
                                    diffFFT_n_relative_abs_real = abs(((code_sig4_chunk_FFT_n[i, fc].real - interpolatedFFTn_real) * 100) / interpolatedFFTn_real)
                                    check2_real = abs(CODE_FACTOR_PERCENT - CODE_FACTOR_PERCENT_DETECTION_THRESHOLD) < diffFFT_n_relative_abs_real < abs(CODE_FACTOR_PERCENT + CODE_FACTOR_PERCENT_DETECTION_THRESHOLD)
                                    diffFFT_n_relative_abs_imag = abs(((code_sig4_chunk_FFT_n[i, fc].imag - interpolatedFFTn_imag) * 100) / interpolatedFFTn_imag)
                                    if CHECK_IMAG_TOO:
                                        check2_imag = abs(CODE_FACTOR_PERCENT - CODE_FACTOR_PERCENT_DETECTION_THRESHOLD) < diffFFT_n_relative_abs_imag < abs(CODE_FACTOR_PERCENT + CODE_FACTOR_PERCENT_DETECTION_THRESHOLD)
                                    else:
                                        check2_imag = True
                                    check2 = (check2_real and check1_real) or (check2_imag and check1_imag)
                                else:
                                    diffFFT_n_relative_abs = abs(((code_sig4_chunk_FFT_n[i, fc].real - interpolatedFFTn) * 100) / interpolatedFFTn)
                                    check2 = abs(CODE_FACTOR_PERCENT - CODE_FACTOR_PERCENT_DETECTION_THRESHOLD) < diffFFT_n_relative_abs < abs(CODE_FACTOR_PERCENT + CODE_FACTOR_PERCENT_DETECTION_THRESHOLD)
                                # .real or .imag in coding range?
                                #################################
                                if check2:
                                    # is this a "skipped" chunk?
                                    ############################
                                    if (skip[i + fc*NR_OF_CHUNKS] == True):
                                        # set error flag to force another iteration
                                        ###########################################
                                        nrOfMsgErr = nrOfMsgErr + 1
                                        # check last forced skip
                                        ########################
                                        if skipForceMinus[i + fc*NR_OF_CHUNKS] == True:
                                            # we reduce ALWAYS coding frequency range below problematic fc
                                            # current fc is screwed up!
                                            # Because this action modifies configuration parameter we need later to
                                            # mark these chunks to be skipped.
                                            ###########################
                                            if (fc != 0):
                                                logging.info("Warning: we are decoding a 2-times-SKIPPED-FORCED bit at i = " + str(i) + " ....for fc = " + str(fc))
                                                logging.info("         We now reduce the number of coding frequencies to "+str(fc))
                                                NR_OF_CODE_FREQUENCIES_TO_CODE = fc
                                                MAX_NR_OF_CODE_FREQUENCIES = int(NR_OF_CODE_FREQUENCIES_TO_CODE / INTERLEAVED_FC)
                                                # TODO: check if we need to uncomment this code
                                                ###############################################
                                                # '''
                                                skip.setall(False)
                                                skipForcePlus.setall(False)
                                                skipForceMinus.setall(False)
                                                # and leave decode loops
                                                leave_loops = True
                                                break
                                                # '''
                                            else:
                                                logging.error("Error: we are decoding a SKIPPED-FORCED bit at i = " + str(i) + " for fc = "+str(fc))
                                                logging.error("       Nr. of bits coded = "+str(nrOfBitsCodedInMsg))
                                                logging.error("       Nr. of bits to code = " + str(LEN_ENCR_MSG_BITS))
                                                if DO_PLOT:
                                                    logging.error("       Check figure 12 to see iteration progress..")
                                                logging.error("       If close to complete, you may try a different password or configuration or just try again. Otherwise you need to select a different/bigger carrier file or reduce your messaage, e.g. split it.")
                                                logging.error("       Alternatively, you may adapt code_frequency_start/end_bin in config.ini but then the recipient of the message shall know the new range as well.")
                                                if DO_PLOT == True:
                                                    input("Press Enter to exit...")
                                                exit(cf.f_lineno)
                                        else:
                                            if skipForcePlus[i + fc*NR_OF_CHUNKS] == True:
                                                skipForcePlus[i + fc*NR_OF_CHUNKS] = False
                                                skipForceMinus[i + fc*NR_OF_CHUNKS] = True
                                            else:
                                                # set always force to PLUS first...
                                                ###################################
                                                skipForcePlus[i + fc*NR_OF_CHUNKS] = True

                                    # do actual decoding here
                                    #########################
                                    if CODE_WITH_MAGNITUDE == True:
                                        if interpolatedFFTn_real != 0.0:
                                            if check2_real == True:
                                                err_sig4_chunk_FFT_percent[i][fc] = (code_sig4_chunk_FFT_n[i, fc].real - interpolatedFFTn_real) * 100.0 / interpolatedFFTn_real
                                            else:
                                                err_sig4_chunk_FFT_percent[i][fc] = (code_sig4_chunk_FFT_n[i, fc].imag - interpolatedFFTn_imag) * 100.0 / interpolatedFFTn_imag
                                        else:
                                            err_sig4_chunk_FFT_percent[i][fc] = 0.0
                                    else:
                                        if interpolatedFFTn != 0.0:
                                            err_sig4_chunk_FFT_percent[i][fc] = (code_sig4_chunk_FFT_n[i,fc].real - interpolatedFFTn) * 100.0 / interpolatedFFTn
                                        else:
                                            err_sig4_chunk_FFT_percent[i][fc] = 0.0
                                # check2
                                # both .real and .imag outside coding range
                                ###########################################
                                else:
                                    # try with recode
                                    #################
                                    if recode[i + fc * NR_OF_CHUNKS] == False:
                                        recode[i + fc * NR_OF_CHUNKS] = True
                                    # try with skip
                                    ###############
                                    else:
                                        recode[i + fc * NR_OF_CHUNKS] = False
                                        # NOTE: err_sig4_chunk_FFT_percent[] will remain zero, this is checked further below i.o. checking for skip[] which is UNKNOWN when reading for the first time
                                        #       if RELATIVE threshold level for detection not reached, then mark chunk to be skipped next time...
                                        ##############################################################################################################################################################
                                        # and mark to skip
                                        skip[i + fc * NR_OF_CHUNKS] = True
                                        if CODE_WITH_MAGNITUDE == True:
                                            logging.debug("SKIP interpolation abs point(" + str(i) + ") = " + str(interpolatedFFTn_real) + "due to EXCEEDED RELATIVE CODING_DELTA for fc = "+str(fc))
                                        else:
                                            logging.debug("SKIP interpolation point(" + str(i) + ") = " + str(interpolatedFFTn) + "due to EXCEEDED RELATIVE CODING_DELTA for fc = "+str(fc))
                            # check1
                            # actual sample outside coding range
                            ####################################
                            else:
                                # try with recode
                                #################
                                if recode[i + fc * NR_OF_CHUNKS] == False:
                                    recode[i + fc * NR_OF_CHUNKS] = True
                                # try with skip
                                ###############
                                else:
                                    recode[i + fc * NR_OF_CHUNKS] = False
                                    # if ABSOLUTE threshold level for detection not reached, then mark to skip next time...
                                    #######################################################################################
                                    # and mark to skip
                                    skip[i + fc * NR_OF_CHUNKS] = True
                                    if CODE_WITH_MAGNITUDE == True:
                                        logging.debug("SKIP interpolation abs point(" + str(i) + ") = " + str(interpolatedFFTn_real) + "due to EXCEEDED ABSOLUTE CODING_DELTA for fc = "+str(fc))
                                    else:
                                        logging.debug("SKIP interpolation point(" + str(i) + ") = " + str(interpolatedFFTn) + "due to EXCEEDED ABSOLUTE CODING_DELTA for fc = "+str(fc))
                        # check
                        # interpolated value outside coding range
                        #########################################
                        else:
                            # try with recode
                            #################
                            if recode[i + fc*NR_OF_CHUNKS] == False:
                                recode[i + fc * NR_OF_CHUNKS] = True
                            # try with skip
                            ###############
                            else:
                                recode[i + fc * NR_OF_CHUNKS] = False
                                # if threshold level for detection not reached, then mark to skip next time...
                                ##############################################################################
                                # and mark to skip
                                skip[i + fc * NR_OF_CHUNKS] = True
                                if CODE_WITH_MAGNITUDE == True:
                                    logging.debug("SKIP interpolation abs point(" + str(i) + ") = " + str(interpolatedFFTn_real) + "due to SKIP_CODING_IF_MAX/MIN_EXCEEDED for fc = " + str(fc))
                                else:
                                    logging.debug("SKIP interpolation point(" + str(i) + ") = " + str(interpolatedFFTn) + "due to SKIP_CODING_IF_MAX/MIN_EXCEEDED for fc = "+str(fc))
                    # ignore bit
                    ############
                    else:
                        logging.debug("Ignoring bit at position "+str(i+fc*NR_OF_CHUNKS))

        # check decoded BIT-STREAM
        ##########################
        code_bitarray_read = bitarray()
        code_sig4_chunk_FFT_percent = np.array([np.zeros(NR_OF_CODE_FREQUENCIES)] * NR_OF_CHUNKS)
        code_abs_gap4 = []
        nrOfBitsDecodedInMsg = 0
        nrOfMsgErr = 0
        # helper variables to detect infinite loops
        nrOfBitsDecodedInMsg_old = 0

        # loop coded/interleaved chunks
        ###############################
        for i in range(1,int(NR_OF_CHUNKS/INTERLEAVED_CHUNKS)):
            # NOTE: we dont get out in order to show PROGRESS on PLOT
            #########################################################
            if False: # getOut == True:
                break
            # loop coding frequencies
            #########################
            for fc in range(0, NR_OF_CODE_FREQUENCIES, INTERLEAVED_FC):
                # Loop as long as message (encrypted org-msg) not yet decoded.
                # NOTE: we coded bits beyond this lenght and they may even be incorrectly coded (above or below threshold),
                #       but we dont care. That is good for "more deceiving" because they are coded in an incorrect way
                #       but attackers dont know that, i.e. they dont know where the message really ends.
                ########################################################################################
                if nrOfBitsDecodedInMsg < LEN_ENCR_MSG_BITS:
                    # ignore bit in msg?
                    ####################
                    if ignore2[i * INTERLEAVED_CHUNKS + fc*NR_OF_CHUNKS] == False:
                        # error in temporary variable
                        #############################
                        err_chunk_FFT = err_sig4_chunk_FFT_percent[i*INTERLEAVED_CHUNKS][fc]

                        # decode not skipped chunks - those above error-threshold (as percentage from interpolated value)
                        #################################################################################################
                        if err_chunk_FFT != 0:
                            nrOfBitsDecodedInMsg = nrOfBitsDecodedInMsg + 1
                            nr_bit_decoded_fc[curr_iteration, fc] = nr_bit_decoded_fc[curr_iteration, fc] + 1
                            if nrOfBitsDecodedInMsg > nrOfBitsCodedInMsg:
                                logging.error("Error: nr. of bits coded lower than nr. of bits decoded ==> " + str(nrOfBitsCodedInMsg) + " != " + str(nrOfBitsDecodedInMsg))
                                break
                            # gaps
                            ######
                            code_abs_gap4 = np.append(code_abs_gap4, abs(err_chunk_FFT))
                            # err to bitarray
                            #################
                            if err_chunk_FFT > 0:
                                code_bitarray_read.append(0)
                            else:
                                code_bitarray_read.append(1)
                            # code to percent value for plotting
                            ####################################
                            if message[nrOfBitsDecodedInMsg-1]:
                                code_sig4_chunk_FFT_percent[i * INTERLEAVED_CHUNKS][fc] = -CODE_FACTOR_PERCENT
                            else:
                                code_sig4_chunk_FFT_percent[i * INTERLEAVED_CHUNKS][fc] = CODE_FACTOR_PERCENT
                            # check MSG against original message
                            ####################################
                            if code_bitarray_read[nrOfBitsDecodedInMsg-1] != message[nrOfBitsDecodedInMsg-1]:
                                nrOfMsgErr = nrOfMsgErr + 1
                                logging.debug("Readback-Error on MSG_ORG["+str(nrOfBitsDecodedInMsg-1)+"] = "+str(message[nrOfBitsDecodedInMsg-1])+" for fc = "+str(fc))
                                # NOTE - IMPORTANT: dont store this case in skip[] !
                                # *** Here we lose synchronization, from now on many erros are actually NOT erros but result of unsynchronized bit-streams ***
                                # We could actually mark the failed bit-coding setting skip[] to true but doing that increases the nr. of discarded
                                # coded-chunks excessively. Instead, we just mark them when reading-back based on the plausibility checks on limits, etc.
                                #########################################################################################################################
                                # set flag getOut to true - getting out of both loops shall "accelerate" processing
                                ###################################################################################
                                getOut = True
                                break
                        # this chunk was not in coding range
                        ####################################
                        else:
                            # not strictly an error because not decoded, so we dont increment nrOfMsgErr
                            # if threshold level for detection not reached, then we could mark to skip next time,
                            # but we dont actually need to do that.
                            #######################################################################################
                            logging.debug("Skipped decoding of bit at chunk position = "+str(i)+" for fc = "+str(fc))
                    # ignore bit
                    ############
                    else:
                        pass
                        # dont need to log again..this was logged further above
                        # logging.debug("Ignore bit at position "+str(i + fc*NR_OF_CHUNKS))
                # message was decoded!
                # ...or we read up to LEN_ENCR_MSG_BITS without reaching yet the expected nrOfBitsDecodedInMsg
                ##############################################################################################
                else:
                    getOut = True
                    break

        # update progress bar and elapsed time
        ######################################
        if DO_LAST == False:
            # update only if decoded bits within message length
            if nrOfBitsDecodedInMsg <= LEN_ENCR_MSG_BITS:
                # we subtract errors to show progress of bits which were "correctly" decoded
                print_progress(nrOfBitsDecodedInMsg-nrOfMsgErr, total_items, prefix='Progress:', suffix='Complete', bar_length=50)
                print("")
                end = timer()
                logging.info("Elapsed time " + str(end - start) + " seconds")
                logging.info("Elapsed time " + str(timedelta(seconds=end - start)))

        # check if nrOfBitsDecodedInMsg > 0
        ###################################
        if nrOfBitsDecodedInMsg == 0:
            logging.error("Error: convergence problems, nrOfBitsDecodedInMsg = "+str(nrOfBitsDecodedInMsg))
            if DO_PLOT == True:
                input("Press Enter to exit...")
            exit(cf.f_lineno)

        # plot err_sig4_chunk_FFT_percent and code_sig4_chunk_FFT_percent
        #################################################################
        if DO_LAST and PLOT_ERR == True:
            plt.figure(9)
            plt.title("err_sig4_chunk_FFT_percent and code_sig4_..")
            if CODE_WITH_MAGNITUDE == True:
                plt.plot(np.abs(err_sig4_chunk_FFT_percent), 'r')
            else:
                plt.plot(np.real(err_sig4_chunk_FFT_percent), 'r')
            plt.plot(code_sig4_chunk_FFT_percent, 'b', label='code')
            plt.grid()
            plt.ion()
            plt.show()
            plt.pause(.001)
            logging.info("Plotted err_sig4_chunk_FFT_percent and code_sig4_..")

        # plot err_sig4_chunk_FFT_absolute and code_sig4_chunk_FFT_percent
        ##################################################################
        if DO_LAST and PLOT_ERR == True:
            plt.figure(10)
            plt.title("err_sig4_chunk_FFT_absolute and code_sig4_..")
            if CODE_WITH_MAGNITUDE == True:
                plt.plot(np.abs(err_sig4_chunk_FFT_absolute), 'r')
            else:
                plt.plot(np.real(err_sig4_chunk_FFT_absolute), 'r')
            plt.plot(code_sig4_chunk_FFT_percent, 'b', label='code')
            plt.grid()
            plt.ion()
            plt.show()
            plt.pause(.001)
            logging.info("Plotted err_sig4_chunk_FFT_absolute and code_sig4_..")

        # plot code_abs_gap4
        #################################
        if DO_LAST and PLOT_ERR == True:
            plt.figure(11)
            plt.title("code_abs_gap4 in percent when coding with CODE_FACTOR_PERCENT = "+str(CODE_FACTOR_PERCENT))
            plt.plot(code_abs_gap4, 'r', label='code_abs_gap4')
            plt.grid()
            plt.ion()
            plt.legend()
            plt.show()
            plt.pause(.001)
            logging.info("Plotted code_abs_gap4")

        # plot nr_bit_decoded as a function of iterations
        ##############################################
        if DO_PLOT:
            if curr_iteration == 1 or DO_LAST == True:
                plt.figure(12)
                plt.title("nr_bit_coded and _decoded for FCs")
            ##############
            plt.plot(nr_bit_coded_fc[:curr_iteration, 0], 'r', label="coded freq = " + str(fc))
            plt.plot(nr_bit_decoded_fc[:curr_iteration, 0], 'c',label="decoded freq = " + str(fc))
            for fc in range(INTERLEAVED_FC, NR_OF_CODE_FREQUENCIES, INTERLEAVED_FC):
                plt.plot(nr_bit_coded_fc[:curr_iteration, fc], 'b', label="coded freq = " + str(fc))
                plt.plot(nr_bit_decoded_fc[:curr_iteration, fc], 'g', label="decoded freq = " + str(fc))
            ##############
            plt.grid()
            plt.ion()
            # plt.legend()  # too many labels to plot
            plt.show()
            plt.pause(.001)
            logging.info("Plotted nr_bit_coded and _decoded for FCs")

        # logging
        #########
        logging.info(">>> Number bits coded = " + str(nrOfBitsCodedInMsg))
        logging.info(">>> Number bits decoded in MSG("+str(len(sig4)/SAMPLING_FREQUENCY)+" sec) = " + str(nrOfBitsDecodedInMsg) + " of a total of max. = "+\
                     str(MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES)+ "(=" + str(MAX_NR_OF_CODED_CHUNKS)+"*"+str(MAX_NR_OF_CODE_FREQUENCIES)+") with fc_start = "+\
                     str(CODE_FREQUENCY_START)+" and "+str(MAX_NR_OF_CODE_FREQUENCIES)+" frequencies coded")
        cbps = nrOfBitsCodedInMsg/(len(sig4)/SAMPLING_FREQUENCY) # coded bits per second
        logging.info(">>> That is, we coded "+str(cbps)+" bits per second in a "+MP3_BITRATE_STR+"bps container")
        # Note: we use SAMPLING_FREQUENCY because we have that nr. of samples in one second when we convert to .WAV (derived from .MP3)
        logging.info(">>> Which means, with Fs = " + str(SAMPLING_FREQUENCY) + ", a capacity of " + str(cbps * 100.0 / (SAMPLING_FREQUENCY * BITS_PER_SAMPLE)) + "%")
        # TODO: print here also capacity based on size of carrier and message files --> size_msg_file_bytes * 100.0 / size_carrier_file_bytes [%]
        logging.info(">>> Number of Skipped bits = " + str(skip.count(1)))
        if (nrOfMsgErr != 0) or (nrOfBitsDecodedInMsg < LEN_ENCR_MSG_BITS):
            logging.info("*** Nr. of bits to code = "+str(LEN_ENCR_MSG_BITS))
            logging.info("*** Nr. of bits coded and decoded => " + str(nrOfBitsCodedInMsg) + " , " + str(nrOfBitsDecodedInMsg))
            logging.info("*** Number of incorrect decoded bits in "+str(curr_iteration)+" iterations = " + str(nrOfMsgErr))
            nr_bit_errs[curr_iteration - 1] = nrOfMsgErr
            nr_bit_coded[curr_iteration - 1] = nrOfBitsCodedInMsg
            nr_bit_decoded[curr_iteration - 1] = nrOfBitsDecodedInMsg
            # got an infinite loop?
            #######################
            if nrOfMsgErr == 0:
                if total_skip_old == 0:
                    total_skip_old = total_skip
                    nrOfBitsDecodedInMsg_old = nrOfBitsDecodedInMsg
                elif (total_skip != total_skip_old) or (nrOfBitsDecodedInMsg != nrOfBitsDecodedInMsg_old):
                    total_skip_old = 0
                    nrOfBitsDecodedInMsg_old = 0
                    pass
                else:
                    logging.error("Error: infinite loop detected!")
                    if DO_PLOT == True:
                        input("Press Enter to exit...")
                    exit(cf.f_lineno)
        elif DO_LAST == False:
            DO_LAST = True
            nr_bit_errs[curr_iteration - 1] = nrOfMsgErr
            nr_bit_coded[curr_iteration - 1] = nrOfBitsCodedInMsg
            nr_bit_decoded[curr_iteration - 1] = nrOfBitsDecodedInMsg
        else:
            # out message to file
            #####################
            # Note: set to True: if during write() you want to manually check that the message is really hidden..
            if False:
                with open(OUT_MESSAGE_FILE_NAME, 'wb') as fh:
                    code_bitarray_read[HEADER_SIZE_BYTES*8:LEN_MSG_BYTES*8].tofile(fh)
                    logging.info(">>> Output message file "+OUT_MESSAGE_FILE_NAME)
            # shorten arrays
            ################
            nr_bit_errs[curr_iteration - 1] = nrOfMsgErr
            nr_bit_coded[curr_iteration - 1] = nrOfBitsCodedInMsg
            nr_bit_decoded[curr_iteration - 1] = nrOfBitsDecodedInMsg
            nr_bit_errs = nr_bit_errs[:curr_iteration]
            nr_bit_coded = nr_bit_coded[:curr_iteration]
            nr_bit_decoded = nr_bit_decoded[:curr_iteration]
            # last infos
            ############
            logging.info(">>> Original message decoded correctly in " + str(curr_iteration) + " iterations!")
            logging.info("psnrErr4 = " + str(psnrErr4))
            logging.info("snrErr4 = " + str(snrErr4))
            # leave loop
            ############
            break # exit for loop "for curr_iteration"

    # end of main loop with MAX_NR_OF_ITERATIONS
    ############################################

    # plot nr_bit_decoded as a function of iterations
    ##############################################
    if PLOT_BIT_ERR_IN_ITERATIONS == True:
        plt.figure(13)
        plt.title("nr_bit_coded and _decoded")
        plt.plot(nr_bit_coded)
        plt.plot(nr_bit_decoded)
        plt.grid()
        plt.ion()
        plt.show()
        plt.pause(.001)
        logging.info("Plotted nr_bit_coded and _decoded")

    # measure time
    end = timer()
    logging.info("Executed program in "+str(end - start)+" seconds")
    logging.info("Executed program in "+str(timedelta(seconds=end - start)))

    # log output file name
    ######################
    print("Embedded " + MESSAGE_FILE_NAME + " in "+ CARRIER_FILE_NAME + " and output result to " + OUT_FILE_NAME)
    if NR_OF_CODE_FREQUENCIES != NR_OF_CODE_FREQUENCIES_TO_CODE:
        print("Warning: NR_OF_CODE_FREQUENCIES changed from "+str(NR_OF_CODE_FREQUENCIES)+" to "+str(NR_OF_CODE_FREQUENCIES_TO_CODE))
        print("         that is, in config.ini you have to use CODE_FREQUENCY_END_BIN = "+str(CODE_FREQUENCY_START_BIN - 1 + NR_OF_CODE_FREQUENCIES_TO_CODE))
        print("         you need this setting when reading!")

    # wait until Enter is pressed..
    # but only if plots are visible,
    # this gives time to analyze them
    #################################
    if DO_PLOT == True:
        input("Press Enter to exit...")

    # end of write() function
    #########################



# read()
#     extract hidden message from stego file
############################################
def read():
    # time measurement
    ##################
    start = timer()

    # current frame
    ###############
    cf = currentframe()
    filename = getframeinfo(cf).filename
    logging.info("(Line nr. "+str(cf.f_lineno)+") Enter read() function in file: " + filename)

    # extract .mp3 metadata, only for information
    #############################################
    tag = TinyTag.get(stego_file)
    logging.info(stego_file+" metadata:")
    logging.info("    duration in seconds = "+str(tag.duration))
    logging.info("    samplerate = " + str(tag.samplerate))
    logging.info("    bitrate = " + str(tag.bitrate))
    logging.info("    channels = " + str(tag.channels))
    logging.info("    comment = " + str(tag.comment))

    # mono?
    #######
    if tag.channels != 1:
        logging.error("Error: no mono file!")
        exit(cf.f_lineno)

    print("Extracting secret message...")

    # local variables
    #################
    SKIP_CODING_IF_MIN_EXCEEDED = SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT
    SKIP_CODING_IF_MAX_EXCEEDED = SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT

    # convert stego file in .wav format to make it readable by code
    ###############################################################
    command = "ffmpeg -loglevel quiet -y -i " + stego_file + " -vn -acodec "+WAV_SAMPLE_FORMAT+" -ac 1 -ar " + str(
        tag.samplerate) + " -f wav " + stego_file + ".wav"
    p1 = subprocess.Popen(shlex.split(command), shell=False, stdout=subprocess.PIPE)
    out, err = p1.communicate()
    if p1.returncode == 0:
        pass
    else:
        logging.error("Error: could not run ffmpeg!")
        exit(cf.f_lineno)
    p1.terminate()
    p1.kill()
    logging.info("Converted " + stego_file + " to " + stego_file + ".wav")

    # read sig4 <- stego_file.wav  (with stego_file.wav <- stego_file.mp3)
    ######################################################################
    sig4, samplerate = sf.read(stego_file + ".wav")
    logging.info("Read " + stego_file + ".wav as sig4")

    # NORMALIZE Settings
    ####################
    if NORMALIZE_SETTINGS == True:
        sig4_max = max(abs(sig4))
        if sig4_max == 0:
            logging.error("Error: sig4_max = 0")
            exit(cf.f_lineno)
        SKIP_CODING_IF_MIN_EXCEEDED = (SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT * sig4_max)
        logging.info("SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT = " + str(
            SKIP_CODING_IF_MIN_EXCEEDED_DEFAULT) + " normalized to " + str(SKIP_CODING_IF_MIN_EXCEEDED))
        SKIP_CODING_IF_MAX_EXCEEDED = (SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT * sig4_max)
        logging.info("SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT = " + str(
            SKIP_CODING_IF_MAX_EXCEEDED_DEFAULT) + " normalized to " + str(SKIP_CODING_IF_MAX_EXCEEDED))

    # del temporary file stego_file.wav
    ###################################
    if KEEP_TEMP_FILES == False:
        if os.path.exists(stego_file + ".wav"):
            os.remove(stego_file + ".wav")
            logging.info("Deleted " + stego_file + ".wav")

    # definitions
    #############
    NR_OF_CHUNKS = int(len(sig4) / CHUNK_LEN_SAMPLES)
    MAX_NR_OF_CODED_CHUNKS = int(NR_OF_CHUNKS / INTERLEAVED_CHUNKS)
    logging.info("MAX_NR_OF_CODED_CHUNKS = " + str(MAX_NR_OF_CODED_CHUNKS))
    MAX_NR_OF_CODE_FREQUENCIES = int(NR_OF_CODE_FREQUENCIES/INTERLEAVED_FC)
    logging.info("MAX_NR_OF_CODE_FREQUENCIES = " + str(MAX_NR_OF_CODE_FREQUENCIES))

    # fill FFT-series
    #################
    code_sig4_chunk_FFT = [np.zeros(CHUNK_LEN_SAMPLES // 2, dtype=complex)] * NR_OF_CHUNKS
    code_sig4_chunk_FFT_n = np.array([np.zeros(NR_OF_CODE_FREQUENCIES, dtype=complex)] * NR_OF_CHUNKS)
    for i in range(NR_OF_CHUNKS):
        code_sig4_part = sig4[i * CHUNK_LEN_SAMPLES:i * CHUNK_LEN_SAMPLES + CHUNK_LEN_SAMPLES]
        code_sig4_chunk_FFT[i] = rfft(code_sig4_part)
        for fcode in range(NR_OF_CODE_FREQUENCIES):
            code_sig4_chunk_FFT_n[i][fcode] = code_sig4_chunk_FFT[i][fcode + CODE_FREQUENCY_START_BIN]

    # bits to be ignored in "message"
    #################################
    ignore2 = bitarray(int(NR_OF_CHUNKS) * NR_OF_CODE_FREQUENCIES)
    ignore2.setall(False)
    if DO_IGNORE_SOME:
        random.seed(SEED_IGNORE)
        for i in range(len(ignore2)):
            if random.random() > IGNORE_THRESHOLD:
                ignore2[i] = 1

    # initialization for progress bar
    #################################
    items = list(range(0, (NR_OF_CHUNKS//INTERLEAVED_CHUNKS)*NR_OF_CODE_FREQUENCIES))
    total_items = len(items)
    print_progress(0, total_items, prefix='Progress:', suffix='Complete', bar_length=50)

    # DECODE stego signal
    # TODO: improvement: read only bits of header, after decoding header correctly read rest bits
    #############################################################################################
    err_sig4_chunk_FFT_percent = np.array([np.zeros(NR_OF_CODE_FREQUENCIES)] * NR_OF_CHUNKS)
    # loop chunks
    #############
    for i in range(INTERLEAVED_CHUNKS, NR_OF_CHUNKS - 1):
        if i % INTERLEAVED_CHUNKS == 0:
            # loop coding frequencies
            #########################
            for fc in range(0, NR_OF_CODE_FREQUENCIES, INTERLEAVED_FC):
                # update progress bar
                #####################
                print_progress(i//INTERLEAVED_CHUNKS*NR_OF_CODE_FREQUENCIES + fc, total_items, prefix='Progress:', suffix='Complete', bar_length=50)
                # ignore bit in message?
                ########################
                if ignore2[i + fc * NR_OF_CHUNKS] == False:
                    # was message coded with magnitude or only .real part?
                    ######################################################
                    if CODE_WITH_MAGNITUDE == True:
                        if AVG_INTERPOLATION == True:
                            plus = np.array([code_sig4_chunk_FFT[i + 1][fc + CODE_FREQUENCY_START_BIN],
                                             code_sig4_chunk_FFT[i + 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                             code_sig4_chunk_FFT[i + 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                            if INTERPOLATE_WITH_MEAN == True:
                                avg_plus = np.mean(plus)
                            else:
                                avg_plus = np.median(plus)
                            minus = np.array([code_sig4_chunk_FFT[i - 1][fc + CODE_FREQUENCY_START_BIN],
                                              code_sig4_chunk_FFT[i - 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                              code_sig4_chunk_FFT[i - 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                            if INTERPOLATE_WITH_MEAN == True:
                                avg_minus = np.mean(minus)
                            else:
                                avg_minus = np.median(minus)
                            diffFFT_n_real = np.real(avg_plus - avg_minus)
                        else:
                            diffFFT_n_real = np.real(code_sig4_chunk_FFT_n[i + 1, fc]) - np.real(
                                code_sig4_chunk_FFT_n[i - 1, fc])
                        interpolatedFFTn_real = abs(
                            code_sig4_chunk_FFT_n[i - 1, fc].real + diffFFT_n_real / 2.0) * np.sign(
                            code_sig4_chunk_FFT_n[i, fc].real)
                        if AVG_INTERPOLATION == True:
                            diffFFT_n_imag = np.imag(avg_plus - avg_minus)
                        else:
                            diffFFT_n_imag = np.imag(code_sig4_chunk_FFT_n[i + 1, fc]) - np.imag(
                                code_sig4_chunk_FFT_n[i - 1, fc])
                        interpolatedFFTn_imag = abs(
                            code_sig4_chunk_FFT_n[i - 1, fc].imag + diffFFT_n_imag / 2.0) * np.sign(
                            code_sig4_chunk_FFT_n[i, fc].imag)
                    # only .real part coded
                    #######################
                    else:
                        if AVG_INTERPOLATION == True:
                            plus = np.array([code_sig4_chunk_FFT[i + 1][fc + CODE_FREQUENCY_START_BIN],
                                             code_sig4_chunk_FFT[i + 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                             code_sig4_chunk_FFT[i + 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                            if INTERPOLATE_WITH_MEAN == True:
                                avg_plus = np.mean(plus)
                            else:
                                avg_plus = np.median(plus)
                            minus = np.array([code_sig4_chunk_FFT[i - 1][fc + CODE_FREQUENCY_START_BIN],
                                              code_sig4_chunk_FFT[i - 1][fc - 1 + CODE_FREQUENCY_START_BIN],
                                              code_sig4_chunk_FFT[i - 1][fc + 1 + CODE_FREQUENCY_START_BIN]])
                            if INTERPOLATE_WITH_MEAN == True:
                                avg_minus = np.mean(minus)
                            else:
                                avg_minus = np.median(minus)
                            diffFFT_n = np.real(avg_plus - avg_minus)
                        else:
                            diffFFT_n = np.real(code_sig4_chunk_FFT_n[i + 1, fc] - code_sig4_chunk_FFT_n[i - 1, fc])
                        ############################################################
                        interpolatedFFTn = abs(code_sig4_chunk_FFT_n[i - 1, fc].real + diffFFT_n / 2.0) * np.sign(
                            code_sig4_chunk_FFT_n[i, fc].real)

                    # flags for plausibility checks
                    ###############################
                    check_real = False
                    check_imag = False

                    # was message coded with magnitude or only .real part?
                    ######################################################
                    if CODE_WITH_MAGNITUDE == True:
                        check_real = SKIP_CODING_IF_MIN_EXCEEDED < abs(interpolatedFFTn_real * INTERPOLATION_FACTOR_PERCENT_MINUS) and \
                                     abs(interpolatedFFTn_real * INTERPOLATION_FACTOR_PERCENT_PLUS) < SKIP_CODING_IF_MAX_EXCEEDED
                        if CHECK_IMAG_TOO:
                            check_imag = SKIP_CODING_IF_MIN_EXCEEDED < abs(interpolatedFFTn_imag * INTERPOLATION_FACTOR_PERCENT_MINUS) and \
                                         abs(interpolatedFFTn_imag * INTERPOLATION_FACTOR_PERCENT_PLUS) < SKIP_CODING_IF_MAX_EXCEEDED
                        else:
                            check_imag = True
                        check = check_real and check_imag
                    # only .real part coded
                    #######################
                    else:
                        check = SKIP_CODING_IF_MIN_EXCEEDED < abs(interpolatedFFTn * INTERPOLATION_FACTOR_PERCENT_MINUS) and \
                                abs(interpolatedFFTn * INTERPOLATION_FACTOR_PERCENT_PLUS) < SKIP_CODING_IF_MAX_EXCEEDED
                    # interpolated value in coding range?
                    #####################################
                    if check:
                        check1_real = False
                        check1_imag = False
                        if CODE_WITH_MAGNITUDE == True:
                            check1_real = SKIP_CODING_IF_MIN_EXCEEDED < abs(code_sig4_chunk_FFT_n[i, fc].real) < SKIP_CODING_IF_MAX_EXCEEDED
                            if CHECK_IMAG_TOO:
                                check1_imag = SKIP_CODING_IF_MIN_EXCEEDED < abs(code_sig4_chunk_FFT_n[i, fc].imag) < SKIP_CODING_IF_MAX_EXCEEDED
                            else:
                                check1_imag = True
                            check1 = (check1_real and check_real) or (check1_imag and check_imag)
                        else:
                            check1 = SKIP_CODING_IF_MIN_EXCEEDED < abs(code_sig4_chunk_FFT_n[i, fc].real) < SKIP_CODING_IF_MAX_EXCEEDED
                        # actual sample in coding range?
                        ################################
                        if check1:
                            check2_real = False
                            if CODE_WITH_MAGNITUDE == True:
                                diffFFT_n_relative_abs_real = abs(((code_sig4_chunk_FFT_n[
                                                                        i, fc].real - interpolatedFFTn_real) * 100) / interpolatedFFTn_real)
                                check2_real = abs(
                                    CODE_FACTOR_PERCENT - CODE_FACTOR_PERCENT_DETECTION_THRESHOLD) < diffFFT_n_relative_abs_real < abs(
                                    CODE_FACTOR_PERCENT + CODE_FACTOR_PERCENT_DETECTION_THRESHOLD)
                                diffFFT_n_relative_abs_imag = abs(((code_sig4_chunk_FFT_n[
                                                                        i, fc].imag - interpolatedFFTn_imag) * 100) / interpolatedFFTn_imag)
                                if CHECK_IMAG_TOO:
                                    check2_imag = abs(
                                        CODE_FACTOR_PERCENT - CODE_FACTOR_PERCENT_DETECTION_THRESHOLD) < diffFFT_n_relative_abs_imag < abs(
                                        CODE_FACTOR_PERCENT + CODE_FACTOR_PERCENT_DETECTION_THRESHOLD)
                                else:
                                    check2_imag = True
                                check2 = (check2_real and check1_real) or (check2_imag and check1_imag)
                            else:
                                diffFFT_n_relative_abs = abs(
                                    ((code_sig4_chunk_FFT_n[i, fc].real - interpolatedFFTn) * 100) / interpolatedFFTn)
                                check2 = abs(
                                    CODE_FACTOR_PERCENT - CODE_FACTOR_PERCENT_DETECTION_THRESHOLD) < diffFFT_n_relative_abs < abs(
                                    CODE_FACTOR_PERCENT + CODE_FACTOR_PERCENT_DETECTION_THRESHOLD)
                            # .real or .imag in coding range?
                            #################################
                            if check2:
                                # do actual decoding here
                                #########################
                                if CODE_WITH_MAGNITUDE == True:
                                    if interpolatedFFTn_real != 0.0:
                                        if check2_real == True:
                                            err_sig4_chunk_FFT_percent[i][fc] = (code_sig4_chunk_FFT_n[i, fc].real - interpolatedFFTn_real) * 100.0 / interpolatedFFTn_real
                                        else:
                                            err_sig4_chunk_FFT_percent[i][fc] = (code_sig4_chunk_FFT_n[i, fc].imag - interpolatedFFTn_imag) * 100.0 / interpolatedFFTn_imag
                                    else:
                                        err_sig4_chunk_FFT_percent[i][fc] = 0.0
                                else:
                                    if interpolatedFFTn != 0.0:
                                        err_sig4_chunk_FFT_percent[i][fc] = (code_sig4_chunk_FFT_n[i, fc].real - interpolatedFFTn) * 100.0 / interpolatedFFTn
                                    else:
                                        err_sig4_chunk_FFT_percent[i][fc] = 0.0
                # ignore bit
                ############
                else:
                    logging.debug("Ignoring bit at position " + str(i + fc * NR_OF_CHUNKS))

    # end of decoding loop
    ######################
    print_progress(i // INTERLEAVED_CHUNKS * NR_OF_CODE_FREQUENCIES + fc + INTERLEAVED_CHUNKS, total_items, prefix='Progress:',suffix='Complete', bar_length=50)
    print()

    # check decoded BIT-STREAM
    ##########################
    code_bitarray_read = bitarray()
    code_sig4_chunk_FFT_percent = np.array([np.zeros(NR_OF_CODE_FREQUENCIES)] * NR_OF_CHUNKS)
    code_abs_gap4 = []
    nrOfBitsDecodedInMsg = 0

    # we set the nr. of bits of the message to HEADER_SIZE_BYTES*8
    # this is all we know for now, the length of the actual message is hidden in the header
    # which needs to be decoded and decrypted first
    ###############################################
    LEN_ENCR_MSG_BITS = HEADER_SIZE_BYTES*8

    # loop coded/interleaved chunks
    ###############################
    for i in range(1, int(NR_OF_CHUNKS / INTERLEAVED_CHUNKS)):
        # Note: we dont get out in order to show PROGRESS on PLOT
        #########################################################
        if False:  # getOut == True:
            break
        # loop coding frequencies
        #########################
        for fc in range(0, NR_OF_CODE_FREQUENCIES, INTERLEAVED_FC):
            # loop as long as message (encrypted org-msg) not yet completely decoded
            # NOTE: we probably coded bits beyond this length and they may even be incorrectly coded (above or below threshold)
            #       but we dont care. That may even be good for "more deceiving" because they are coded in an incorrect way
            #       but attackers dont know that.
            ###################################################################################################################
            if nrOfBitsDecodedInMsg < LEN_ENCR_MSG_BITS:
                # ignore bit in msg?
                ####################
                if ignore2[i * INTERLEAVED_CHUNKS + fc * NR_OF_CHUNKS] == False:
                    # error in temporary variable
                    #############################
                    err_chunk_FFT = err_sig4_chunk_FFT_percent[i * INTERLEAVED_CHUNKS][fc]

                    # decode not skipped chunks - coding is found above error-threshold (as percentage from interpolated value)
                    ###########################################################################################################
                    if err_chunk_FFT != 0:
                        nrOfBitsDecodedInMsg = nrOfBitsDecodedInMsg + 1
                        # gaps
                        ######
                        code_abs_gap4 = np.append(code_abs_gap4, abs(err_chunk_FFT))
                        # err to bitarray
                        #################
                        if err_chunk_FFT > 0:
                            code_bitarray_read.append(0)
                        else:
                            code_bitarray_read.append(1)
                        # can we now decode header?
                        ###########################
                        if nrOfBitsDecodedInMsg == HEADER_SIZE_BYTES*8:
                            # first transform bitarray to bytes,
                            # then decrypt,
                            # then find # == 35, which is the end of the header before padding
                            ##################################################################
                            bytes_temp = code_bitarray_read[:HEADER_SIZE_BYTES * 8].tobytes()
                            try:
                                header_bytes = fernet.decrypt(bytes_temp)
                            except Exception:
                                if logging_level == logging.DEBUG:
                                    traceback.print_exc()
                                logging.error("Error: could not decrypt header. Corrupt file, wrong password or option -m forgotten!")
                                logging.error("       Make sure to use the same codec as the one used during embedding. Current ffmpeg version = "+FFMPEG_VERSION)
                                exit(cf.f_lineno)
                            index_end = header_bytes.find(b'#')
                            if index_end != 0:
                                header = header_bytes[:index_end].decode('utf-8')
                                logging.info("Decoded header correclty = "+header)
                                # now set actual value of LEN_ENCR_MSG_BITS derived from LEN_MSG_BYTES
                                ######################################################################
                                idx_comma = header.rfind(',')
                                LEN_MSG_BYTES = int(header[idx_comma+1:])
                                LEN_ENCR_MSG_BITS = (LEN_MSG_BYTES*8//64)*64 + 64
                                # is LEN_ENCR_MSG_BITS plausible?
                                if(LEN_ENCR_MSG_BITS > MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES):
                                    logging.error("Error: message too large! msg_len_bits = "+str(LEN_ENCR_MSG_BITS)+", MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES = "+str(MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES))
                                    logging.error("       If close to complete, you may try a different password or configuration or just try again. Otherwise you need to select a different/bigger carrier file or reduce your messaage, e.g. split it.")
                                    if DO_PLOT == True:
                                        input("Press Enter to exit...")
                                    exit(cf.f_lineno)
                                else:
                                    logging.info("In principle, the Message fits inside the carrier, msg_len_bits = " + str(LEN_ENCR_MSG_BITS) + " < MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES = " + str(MAX_NR_OF_CODED_CHUNKS*MAX_NR_OF_CODE_FREQUENCIES))
                                # find file-name of secret-message-file
                                #######################################
                                idx_2nd_comma = header[:idx_comma-1].rfind(',')
                                if FILE_NAME_HDR == "":
                                    FILE_NAME_HDR_1 = header[idx_2nd_comma+1:idx_comma]
                                else:
                                    FILE_NAME_HDR_1 = FILE_NAME_HDR
                                # find out if the file is encrypted and/or compressed
                                #####################################################
                                ENCRYPTION1 = bool(int(header[idx_2nd_comma - 1:idx_2nd_comma]))
                                COMPRESSION1 = bool(int(header[idx_2nd_comma - 2:idx_2nd_comma - 1]))
                            else:
                                logging.error("Error: header could not be decoded correctly!")
                                logging.error("       Make sure to use the same codec as the one used during embedding. Current ffmpeg version = "+FFMPEG_VERSION)
                                exit(cf.f_lineno)
                    # this chunk was not in coding range
                    ####################################
                    else:
                        logging.debug("Skipped decoding of bit at chunk position = " + str(i) + " for fc = " + str(fc))
                # ignore bit
                ############
                else:
                    pass
                    # dont need to log again..that was done further above
                    # logging.debug("Ignore bit in position "+str(i + fc*NR_OF_CHUNKS))
            # header was read...and message was decoded!
            # there may be errors, but we'll find out later while decrypting and/or decompressing the message
            #################################################################################################
            else:
                getOut = True
                break

    # check if nrOfBitsDecodedInMsg > 0
    ###################################
    if nrOfBitsDecodedInMsg == 0:
        logging.error("Error: convergence problems, nrOfBitsDecodedInMsg = " + str(nrOfBitsDecodedInMsg))
        if DO_PLOT == True:
            input("Press Enter to exit...")
        exit(cf.f_lineno)

    # plot err_sig4_chunk_FFT_percent and code_sig4_chunk_FFT_percent
    #################################################################
    if PLOT_ERR == True:
        plt.figure(9)
        plt.title("err_sig4_chunk_FFT_percent and code_sig4_..")
        if CODE_WITH_MAGNITUDE == True:
            plt.plot(np.abs(err_sig4_chunk_FFT_percent), 'r', label='err')
        else:
            plt.plot(np.real(err_sig4_chunk_FFT_percent), 'r', label='err')
        plt.plot(code_sig4_chunk_FFT_percent, 'b', label='code')
        plt.grid()
        plt.ion()
        # plt.legend() # too many labels to show..
        plt.show()
        plt.pause(.001)
        logging.info("Plotted err_sig4_chunk_FFT_percent and code_sig4_..")

    # out message to file
    #####################
    OUT_MSG_FILE = OUT_DIR_NAME + FILE_NAME_HDR_1
    with open(OUT_MSG_FILE, 'wb') as fh:
        if ENCRYPTION1 == True:
            print("Decrypting message file..")
            bytes_rx = code_bitarray_read[HEADER_SIZE_BYTES*8:LEN_MSG_BYTES*8].tobytes()
            bytes_decrypted = fernet.decrypt(bytes_rx)
            if COMPRESSION1 == True:
                len_msg_compressed = len(bytes_decrypted)
                bytes_decrypted = zlib.decompress(bytes_decrypted)
                compression_ratio = float(len(bytes_decrypted))/float(len_msg_compressed)
                logging.info("Decompressed msg with ratio = " + str(compression_ratio))
            fh.write(bytes_decrypted)
        else:
            if COMPRESSION1 == False:
                code_bitarray_read[HEADER_SIZE_BYTES*8:LEN_MSG_BYTES*8].tofile(fh)
            else:
                bytes_rx = code_bitarray_read[HEADER_SIZE_BYTES * 8:LEN_MSG_BYTES * 8].tobytes()
                bytes_decompressed = zlib.decompress(bytes_rx)
                compression_ratio = float(len(bytes_decompressed))/float(len(bytes_rx))
                logging.info("Decompressed msg with ratio = " + str(compression_ratio))
                fh.write(bytes_decompressed)

    # hide output file?
    ###################
    if HIDE == True:
        # TODO: correct Issue: [B607:start_process_with_partial_path]
        OUT_MSG_FILE = OUT_DIR_NAME + FILE_NAME_HDR_1
        subprocess.check_call(["attrib", "+h", OUT_MSG_FILE])
        logging.info("Hidden " + OUT_MSG_FILE)

    # logging
    #########
    logging.info(">>> Original MSG decoded correctly")
    logging.info(">>> Number bits decoded in MSG(" + str(len(sig4) / tag.samplerate) + " sec) = " + str(
        nrOfBitsDecodedInMsg) + " of a total of max. = " + str(
        MAX_NR_OF_CODED_CHUNKS * MAX_NR_OF_CODE_FREQUENCIES) + "(=" + str(
        MAX_NR_OF_CODED_CHUNKS) + "*" + str(
        MAX_NR_OF_CODE_FREQUENCIES) + ") with fc_start = " + str(CODE_FREQUENCY_START) + " and " + str(
        MAX_NR_OF_CODE_FREQUENCIES) + " frequencies coded")
    cbps = nrOfBitsDecodedInMsg / (len(sig4) / tag.samplerate)  # coded bits per second
    logging.info(">>> That is, we decoded " + str(cbps) + " bits per second in a " + str(tag.bitrate)+"k" + "bps container")
    # Note: we use SAMPLING_FREQUENCY because we have that nr. of samples in one second when we convert to .WAV (derived from .MP3)
    logging.info(">>> Which means, with Fs = " + str(tag.samplerate) + ", a capacity of " + str(cbps * 100.0 / (tag.samplerate*BITS_PER_SAMPLE)) + "%")

    # measure time
    ##############
    end = timer()
    logging.info(">>> Executed program in "+str(end - start)+" seconds")
    logging.info(">>> Executed program in "+str(timedelta(seconds=end - start)))

    # log output file name
    ######################
    if HIDE == False:
        print("Extracted " + OUT_MSG_FILE + " from " + stego_file)
    else:
        print("Extracted " + OUT_MSG_FILE + " (hidden) from " + stego_file)

    # wait until Enter is pressed..
    # but only if plots are visible,
    # this gives time to analyze them
    #################################
    if DO_PLOT == True:
        input("Press Enter to exit...")

    # end of read()
    ###############



# main()
########
def main():
    if stego_file != "": # not isinstance(args.read, type(None)):
        read()
    else:
        write()



# psnr()
########
def psnr(array1, array2, max_value):
    mse = np.mean((array1 - array2) ** 2.0)
    if mse == 0:
        return 100.0
    return 20.0 * math.log10(max_value / math.sqrt(mse))



# snr()
#######
def snr(array1, array2):
    length = len(array1)
    snr = 0.0;
    ASig = 0.0;
    ADiff = 0.0;
    for i in range(length):
        ASig = ASig + (array1[i]) ** 2.0
        ADiff = ADiff + (array2[i] - array1[i]) ** 2.0
    ASig = math.sqrt(ASig / length)
    ADiff = math.sqrt(ADiff / length)
    if (ASig != 0.0) & (ADiff != 0.0):
        snr = 20.0 * math.log10(ASig / ADiff)
    return snr



# execute main function
#######################
if __name__ == '__main__':
    main()


