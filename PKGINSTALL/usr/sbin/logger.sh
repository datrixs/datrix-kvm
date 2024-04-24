#!/usr/bin/env bash
# author: wu.changwen

# 日志级别 debug-1, info-2, warn-3, error-4, always-5
# shellcheck disable=SC2034
LOG_LEVEL=2
LOG_FILE=$1

# debug log
function log_debug() {
  content="[DEBUG]$(date '+%Y-%m-%d %H:%M:%S') $@"
  [ $LOG_LEVEL -le 1 ] && echo -e "\033[32m" "${content}" "\033[0m" && echo "${content}" >> "$LOG_FILE" 2>&1
}

# info log
function log_info() {
  content="[INFO]$(date '+%Y-%m-%d %H:%M:%S') $@"
  [ $LOG_LEVEL -le 2 ] && echo -e "\033[32m" "${content}" "\033[0m" && echo "${content}" >> "$LOG_FILE" 2>&1
}

# warning log
function log_warning {
  content="[WARNING]$(date '+%Y-%m-%d %H:%M:%S') $@"
  [ $LOG_LEVEL -le 3 ] && echo -e "\033[33m" "${content}" "\033[0m" && echo "${content}" >> "$LOG_FILE" 2>&1
}

# error log
function log_error {
  content="[ERROR]$(date '+%Y-%m-%d %H:%M:%S') $@"
  [ $LOG_LEVEL -le 4 ] && echo -e "\033[31m" "${content}" "\033[0m" && echo "${content}" >> "$LOG_FILE" 2>&1
}

# Always log
function log_always {
  content="[Always]$(date '+%Y-%m-%d %H:%M:%S') $@"
  [ $LOG_LEVEL -le 5 ] && echo -e "\033[32m" "${content}" "\033[0m" && echo "${content}" >> "$LOG_FILE" 2>&1
}
