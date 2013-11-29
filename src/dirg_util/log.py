# -*- coding: utf-8 -*-
#
# Copyright (C) Umeå University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#            http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging
from logging.handlers import BufferingHandler


def create_logger(filename):
    """
    Creates a logger with a given filename.
    :param filename: File name for the log
    :return: A logger class.
    """
    logger = logging.getLogger("")
    logfile_name = filename
    handler = logging.FileHandler(logfile_name)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")
    cpc = ('%(asctime)s %(name)s:%(levelname)s '
           '[%(client)s,%(path)s,%(cid)s] %(message)s')
    handler.setFormatter(base_formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    _formatter = logging.Formatter(cpc)
    fil_handler = logging.FileHandler(logfile_name)
    fil_handler.setFormatter(_formatter)

    buf_handler = BufferingHandler(10000)
    buf_handler.setFormatter(_formatter)
    return logger
