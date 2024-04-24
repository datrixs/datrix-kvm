package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/kr/pretty"
	"datrixinfo.com/rcc/AutoUpgrade/netlink"
)

const (
	// UnPackPasswod        = "Datrixinfo$!2023!"
	MonitorAction        = "add"
	DevType              = "partition"
	BasePasswordPackName = "rcc-pikvmd-box-base.tar.gz"
	BasePackPath         = "/media/linaro"
)

var (
	filePath              *string
	monitorMode, infoMode *bool
)

func main() {
	matcher, err := getOptionnalMatcher()
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("Monitoring UEvent kernel message to user-space...")
	conn := new(netlink.UEventConn)
	if err := conn.Connect(netlink.UdevEvent); err != nil {
		log.Fatalln("Unable to connect to Netlink Kobject UEvent socket")
	}
	defer conn.Close()

	queue := make(chan netlink.UEvent)
	errors := make(chan error)
	quit := conn.Monitor(queue, errors, matcher)

	// Signal handler to quit properly monitor mode
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		<-signals
		log.Println("Exiting monitor mode...")
		close(quit)
		os.Exit(0)
	}()

	// Handling message from queue
	for {
		select {
		case uevent := <-queue:
			if uevent.Action == MonitorAction {
				dev_type, ok := uevent.Env["DEVTYPE"]
				if ok && dev_type == DevType {
					time.Sleep(time.Second * 20)
					log.Println("Handle", pretty.Sprint(uevent))
					PackFile, err := FindPack(BasePackPath)
					if err != nil {
						log.Println("Not need to Install, ", err)
					} else {
						log.Println("KVMD Packages: ", PackFile)
						Install(PackFile)
					}
				}
			}

		case err := <-errors:
			log.Println("ERROR:", err)
		}
	}

}

// getOptionnalMatcher Parse and load config file which contains rules for matching
func getOptionnalMatcher() (matcher netlink.Matcher, err error) {
	if filePath == nil || *filePath == "" {
		return nil, nil
	}

	stream, err := ioutil.ReadFile(*filePath)
	if err != nil {
		return nil, err
	}

	if stream == nil {
		return nil, fmt.Errorf("Empty, no rules provided in \"%s\", err: %w", *filePath, err)
	}

	var rules netlink.RuleDefinitions
	if err := json.Unmarshal(stream, &rules); err != nil {
		return nil, fmt.Errorf("Wrong rule syntax, err: %w", err)
	}

	return &rules, nil
}

func FindPack(pathName string) (string, error) {
	log.Printf("path Name-----> %s", pathName)
	fis, err := ioutil.ReadDir(pathName)
	if err != nil {
		log.Printf("Read Path %s, error: %s", pathName, err)
		return "", err
	}

	for _, fi := range fis {
		fullname := pathName + "/" + fi.Name()
		if fi.IsDir() {
			tempfile, err := FindPack(fullname)
			if err != nil {
				return "", err
			}
			return tempfile, nil
		} else {
			if fi.Name() == BasePasswordPackName {
				return fullname, nil
			}
		}
	}

	return "", fmt.Errorf("Not Found the available installation packages of kvmd")
}

func Install(FullPackName string) {
	// 处理加密包提取安装包
	// UnPasswordcmd := exec.Command("unzip", "-P", UnPackPasswod, FullPackName, "-d", UnPackPath)
	// out, err := UnPasswordcmd.CombinedOutput()
	// log.Printf("Unpack Out: %s", string(out))
	// if err != nil {
	// 	log.Printf("\nUnpack %s failed, Error Out: %s", FullPackName, err)
	// 	os.Exit(1)
	// }

	log.Println("Start to Install PiKVMD packages")
	InstallCmd := exec.Command("tar", "-zxvf", FullPackName, "-C", "/")
	if err := InstallCmd.Run(); err != nil {
		log.Println("Install PiKVMD Failed...")
		return
	}

	log.Printf("Install PiKVMD Package of %s Suceessfully..., will to reboot", FullPackName)

	rebootCmd := exec.Command("reboot")
	if err := rebootCmd.Run(); err != nil {
		log.Println("Reboot system Failed...")
	}
}
