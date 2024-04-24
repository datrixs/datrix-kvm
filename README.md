# KVM
Datrix KVM基于pikvm项目进行修改后适配rk，实现远程监控和控制设计的IP KVM设备，可以将电脑主机的视频、鼠标和键盘通过网络连接到远程控制台，实现对主机的远程管理，设备同时也提供了本地控制台的连接端口，支持在本地对主机进行管理。

* 安装包的目录结构

安装包的执行顺序 apps2、apps1、apps

```
|
|--- RCC-KVMD1.0.0
|    |--- kvmdbox
|         |--- apps (KVMD服务的安装包)
|         |    |--- pikmvd-backend    KVMD业务程序
|         |--- apps1
|         |    |--- deb   基础环境deb包
|         |    |--- py    python第三方包
|         |--- apps2
|         |    |--- bin   # 对应系统的 /bin 目录 
|         |    |--- etc   # 对应系统的 /etc 目录
|         |    |--- lib   # 对应系统的 /lib 目录
|         |    |--- opt   # 对应系统的 /opt 目录
|         |    |--- sbin  # 对应系统的 /sbin 目录
|         |    |--- usr   # 对应系统的 /usr 目录
|         |--- appsh   (apps包装脚本)
|         |--- appsh1  (apps1包安装脚本)
|         |--- appsh2  (apps2包安装脚本)
|         |--- md5sum
|         |--- version
```

* 平台侧升级包结构
```
RCC-KVMD-2.3.0
|
|--- md5sum.txt
|--- RccKVMD.zip
|--- pkginfo
```

* kvm info

```
kvm default user and password：linaor/linaro
```

* [kvm-install](https://github.com/datrixs/datrix-kvm-install)

* janus related files

```
mkdir -p /usr/lib/ustreamer/janus
cp libjanus_ustreamer.so /usr/lib/ustreamer/janus/

cp /usr/lib/libsrtp2.so* /usr/lib/aarch64-linux-gnu/
ldconfig

/usr/share/janus/javascript
modify adapter.js, janus.js
```

```
ln -s /bin/ip /usr/bin/ip

ln -s /bin/systemctl /usr/bin/systemctl

mkdir /usr/share/tessdata
```

* hw config and udev rules config

```
/etc/init.d/.usb_config: delete contents in the file
/etc/udev/rules.d/99-kvmd.rules
/etc/udev/rules.d/95-kvm-io-access.rules
/opt/vc/bin/vcgencmd
```

* kvmd config

```
/etc/kvmd/override.yaml
Temporary workaround: disable msd and atx
/etc/kvmd/overide.yaml
cmd:/usr/local/bin/ustreamer
```

* systemd unit file config

```
/usr/lib/systemd/system/kvmd*
change Exec path (temperory workaround)
```

* 全量打包

```
tar -cvpzf rcc-box.tar.gz --exclude=/boot --exclude=/data --exclude=/sys --exclude=/dev --exclude=/home --exclude=/lost+found --exclude=/media --exclude=/mnt --exclude=/oem --exclude=/proc --exclude=/root --exclude=/run --exclude=/sdcard --exclude=/srv --exclude=/system --exclude=/tmp --exclude=/udisk --exclude=/userdata --exclude=/var --exclude=/vendor --exclude=/rockchip-test  --exclude=/usr/local/lib/python3.10/*/__pycache__ /
```

# Special thanks
* [Pikvm](https://github.com/pikvm)
* [Pikvm UStreamer](https://github.com/pikvm/ustreamer)