s/console=ttyAMA0\,115200//g
s/kgdboc=ttyAMA0\,115200//g
s/console=serial0\,115200//g
s/kgdboc=serial0\,115200//g
s/rootwait/cma=128M rootwait/g
