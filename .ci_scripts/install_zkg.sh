#!/bin/bash

export PATH="/opt/zeek/bin:/opt/zeek/bin:$PATH"

pip3 install -U sphinx_rtd_theme zkg
zkg autoconfig
