#!/usr/bin/env python3
"""
Main for gitlab sync
"""
# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,import-error,no-member

import time
import schedule
from gitlab_sync import GitlabSync

def sync():
    """
    Execute sync task
    """
    gitlab_sync = GitlabSync()
    gitlab_sync.sync()

if __name__ == "__main__":
    schedule.every(30).minutes.do(sync)
    schedule.run_all()
    while 1:
        schedule.run_pending()
        time.sleep(30)
