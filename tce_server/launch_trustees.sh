#!/bin/sh
fab run_trustee:1 &
fab run_trustee:2 &
fab run_trustee:3 &

#
#fab run_trustee:1 >&1.log &
#fab run_trustee:2 >&2.log &
#fab run_trustee:3 >&3.log &