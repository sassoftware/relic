#!/bin/bash
git describe --tags --dirty=+ |sed -e 's/-\([0-9]*\).*/+\1/' | sed -e 's/^v//'
