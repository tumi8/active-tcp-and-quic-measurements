#!/bin/bash

cd /home/debian/repo/ma-schwarzenberg/
source venv/bin/activate
python code/madns/madns/dns.py /srv/data/madns /srv/data/madns/dnscfg.json
deactivate