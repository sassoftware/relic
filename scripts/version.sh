#!/bin/bash
git describe --tags --dirty=+ |sed -e 's/-\([0-9]*\).*/+/' | sed -e 's/^v//'
