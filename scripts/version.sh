#!/bin/bash
git describe --tags |sed -e 's/-\([0-9]*\).*/.\1/'
