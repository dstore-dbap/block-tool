#! /usr/bin/env python
# -*- coding: iso-8859-1 -*-
import time
true = True
false = False
now = str(time.time()).split('.')[0] + "000"
now = int(now)
queries = {'match_all': {"query": {"match_all": {}}, "size": 1}}
