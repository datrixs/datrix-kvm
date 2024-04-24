#!/usr/bin/env bash
# author: wu.changwen

# shellcheck disable=SC2034
pack_path="/home/tmp/pack"
log_file="/var/log/upgrade.log"
back_pack="/home/tmp/pack/rcc-box.tar.gz"
version_file="/home/tmp/pack/version"

source /usr/sbin/logger.sh ${log_file}

rm -rf ${log_file}
# Stop service Nginx、Kvmd、Ustreamer、Janus、node_exporter、gpio-check
function StopService() {
  log_info "Start to stop Services"

  systemctl stop kvmd-nginx.service
  # shellcheck disable=SC2181
  if [ $? -ne 0 ]; then
    log_error "Stop Kvmd-nginx service fail..."
  fi

  systemctl stop kvmd-janus.service
  # shellcheck disable=SC2181
  if [ $? -ne 0 ]; then
    log_error "Stop Kvmd-janus service fail..."
  fi

  systemctl stop gpio-check.service
  # shellcheck disable=SC2181
  if [ $? -ne 0 ]; then
    log_error "Stop gpio-check service fail..."
  fi

  systemctl stop node_exporter.service
  # shellcheck disable=SC2181
  if [ $? -ne 0 ]; then
    log_error "Stop node_exporter service fail..."
  fi

  # systemctl stop kvmd.service
  # # shellcheck disable=SC2181
  # if [ $? -ne 0 ]; then
  #   log_error "Stop Kvmd service fail..."
  # fi
}

# Back Box System
function backSystem() {
  log_info "Start to Back System"
  # shellcheck disable=SC2164
  if [ -d ${pack_path} ]; then
    cd ${pack_path}
  else
    log_error "There are not pack to upgrade"
    exit 1
  fi

  excludes=(boot data sys dev home lost+found media mnt oem proc root run sdcard srv system tmp udisk userdata var vendor rockchip-test)
  paras=""
  # shellcheck disable=SC2068
  for ele in ${excludes[@]}
  do
    paras=${paras}" --exclude=/"${ele}
  done

  tar -cvpzf rcc-box.tar.gz ${paras}  --exclude=/usr/local/lib/*/__pycache__ --exclude=/usr/lib/debug/.build-id/ /
  # shellcheck disable=SC2181
  if [ $? -ne 0 ]; then
    log_error "Back System fail"
    if [ -e ${back_pack} ]; then
      rm -rf ${back_pack}
    fi
    # shellcheck disable=SC1073
    exit 1
  fi
  log_info "Back System ok..."
}

# Install base app
function install_app2() {
  base_pack="/home/tmp/pack/apps2"
  base_sh="/home/tmp/pack/appsh2"
  log_info "Start to upgrade app2 Application"
  if [ -d ${pack_path} ]; then
    # shellcheck disable=SC2164
    cd ${pack_path}
  else
    log_error "There are not pack to upgrade"
    exit 1
  fi

  # 校验Base包是否存在
  if [ ! -e ${base_pack} ]; then
    log_warning "The app2 does not need to be upgrade"
    return 0
  fi

   # 校验Base包的升级脚本是否存在
    if [ ! -e ${base_sh} ]; then
      log_warning "The app2 does not need to be upgrade"
      return 0
    fi

  bash ${base_sh}
  # shellcheck disable=SC2181
  if [ $? -ne 0 ]; then
    recodeshell=`python3 -c 'import asyncio; from kvmd.apps.kvmd.report_log import record_log; print(asyncio.run(record_log(0)))'`
    if [ $recodeshell -ne 1 ]; then
      log_error "upgrade log recode failed"
    fi
    log_error "Upgrade Base Application fail"
    tar -zxvf ${back_pack} -C / && rm -rf ${back_pack}
    return 1
  fi

  return 0
}

# Install app1
function install_app1() {
  app1_pack="/home/tmp/pack/apps1"
  app1_sh="/home/tmp/pack/appsh1"
  log_info "Start to upgrade app1 Application"

  if [ -d ${pack_path} ]; then
    # shellcheck disable=SC2164
    cd ${pack_path}
  else
    log_error "There are no pack to upgrade"
    exit 1
  fi

  # 校验app1包是否存在
  if [ ! -e ${app1_pack} ]; then
    log_warning "The app1 does not need to be upgrade"
    return 0
  fi

  if [ ! -e ${app1_sh} ]; then
    log_warning "The app1 does not need to be upgrade"
    return 0
  fi

  bash ${app1_sh}
  # shellcheck disable=SC2181
  if [ $? -ne 0 ]; then
    recodeshell=`python3 -c 'import asyncio; from kvmd.apps.kvmd.report_log import record_log; print(asyncio.run(record_log(0)))'`
    if [ $recodeshell -ne 1 ]; then
      log_error "upgrade log recode failed"
    fi
    log_error "Upgrade app1 Application fail..."
    return 1
  fi

  return 0
}

# Install app
function install_app() {
  app_pack="/home/tmp/pack/apps"
  app_sh="/home/tmp/pack/appsh"
  log_info "Start to Upgrade app Application"

  if [ -d ${pack_path} ]; then
    # shellcheck disable=SC2164
    cd ${pack_path}
  else
    log_error "There are no pack to upgrade"
    exit 1
  fi

  # 校验app1包是否存在
  if [ ! -e ${app_pack} ]; then
    log_warning "The app does not need to be upgrade"
    return 0
  fi

  if [ ! -e ${app_sh} ]; then
    log_warning "The app does not need to be upgrade"
    return 0
  fi

  bash ${app_sh}
  # shellcheck disable=SC2181
  if [ $? -ne 0 ]; then
    recodeshell=`python3 -c 'import asyncio; from kvmd.apps.kvmd.report_log import record_log; print(asyncio.run(record_log(0)))'`
    if [ $recodeshell -ne 1 ]; then
      log_error "upgrade log recode failed"
    fi
    log_error "Upgrade app Application fail..."
    return 1
  fi

  return 0
}

function RestoreSystem() {
  log_info "Start to Restore system..."
  if [-e ${back_pack} ]; then
    tar -zxvf ${back_pack} -C /
    if [ $? -ne 0 ]; then
      log_error "Restore system fail"
    else
      rm -rf ${back_pack}
    fi
  fi
}

log_info "Start Upgrade KVMD box System & Services"
StopService
# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
  log_error "Stop Service error"
  reboot
fi

#  系统备份功能
# backSystem
# # shellcheck disable=SC2181
# if [ $? -ne 0 ]; then
#   log_error "Back Box System & Services fail"
#   if [ -e ${back_pack} ]; then
#     rm -rf ${back_pack}
#   fi
#   reboot
# fi

install_app2
# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
  log_error "Upgrade app2 fail"
  recodeshell=`python3 -c 'import asyncio; from kvmd.apps.kvmd.report_log import record_log; print(asyncio.run(record_log(0)))'`
  if [ $recodeshell -ne 1 ]; then
    log_error "upgrade log recode failed"
  fi
  RestoreSystem
  reboot
fi

install_app1
# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
  log_error "Upgrade app1 fail"
  recodeshell=`python3 -c 'import asyncio; from kvmd.apps.kvmd.report_log import record_log; print(asyncio.run(record_log(0)))'`
  if [ $recodeshell -ne 1 ]; then
    log_error "upgrade log recode failed"
  fi
  RestoreSystem
  reboot
fi

install_app
# shellcheck disable=SC2181
if [ $? -ne 0 ]; then
  log_error "Upgrade app fail"
  recodeshell=`python3 -c 'import asyncio; from kvmd.apps.kvmd.report_log import record_log; print(asyncio.run(record_log(0)))'`
  if [ $recodeshell -ne 1 ]; then
    log_error "upgrade log recode failed"
  fi
  RestoreSystem
  reboot
fi

if [ -e ${version_file} ]; then
  # shellcheck disable=SC2154
  cp -rf "${version_file}" /app
else
  log_error "Replace /app/version fail"
fi

rm -rf ${pack_path}

recodeshell=`python3 -c 'import asyncio; from kvmd.apps.kvmd.report_log import record_log; print(asyncio.run(record_log(1)))'`
if [ $recodeshell -ne 1 ]; then
  log_error "upgrade log recode failed"
fi

log_info "Complete to upgrade"
reboot