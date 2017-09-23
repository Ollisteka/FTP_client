#!/bin/bash
coverage3 erase
coverage3 run -m unittest discover
coverage3 report -m
