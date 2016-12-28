#!/bin/bash
#
#
#

CURATOR_DIR=/home/azmin/hyeoncheon-elastic/setup
CURATOR_CONF=$CURATOR_DIR/curator.yml
CURATOR_ACTIONS=$CURATOR_DIR/close.yml

curator --config $CURATOR_CONF $CURATOR_ACTIONS > $CURATOR_DIR/curator.lastlog

