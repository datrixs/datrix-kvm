import logging
import socket
import threading

import gpiod

# 日志格式配置
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - [%(levelname)s] - %(message)s',
                    datefmt='%Y-%m-%d,%H:%M:%S')

socket_ip, socket_port = "0.0.0.0", 5557

chip_line_led_list = []
chip_line_dict = dict()
old_chip_code_dict = dict()

# 权限控制开关
CHIP_SEQ_PERMISSION_BUTTON = "gpiochip0"
CHIP_LINE_PERMISSION_BUTTON = 14
chip_line_dict["CHIP_SEQ_PERMISSION_BUTTON" + CHIP_SEQ_PERMISSION_BUTTON] = CHIP_LINE_PERMISSION_BUTTON
old_chip_code_dict[CHIP_LINE_PERMISSION_BUTTON] = 0


def socket_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.bind((socket_ip, socket_port))
    server_socket.listen(5)

    logging.info("button socket server start succeed !!!")
    while True:
        sock, addr = server_socket.accept()
        chip_monitor(sock=sock, addr=addr)


def get_chip_line_list():
    if not chip_line_led_list:
        set_chip_line_list()
    return chip_line_led_list


def set_chip_line_list():

    # 区分红黄绿信号线，报警线，发送不同代码
    for chip_seq, chip_line in chip_line_dict.items():
        chip = gpiod.Chip(chip_seq.replace("CHIP_SEQ_PERMISSION_BUTTON", ""))
        led = chip.get_line(chip_line)
        led.request(consumer=str(chip_line), type=gpiod.LINE_REQ_DIR_IN)
        chip_line_led_list.append(dict(led=led, chip_seq=chip_seq, chip_line=chip_line))


def get_chip_value(sock, chip_line_led):
    """

    :param sock:
    :param chip_line_led:
    :return:
    """

    logging.info("get_chip_value chip_line_led value: {}".format(str(chip_line_led)))

    last_chip_value_dict = dict()

    # 区分红黄绿信号线，报警线，发送不同代码
    while True:

        chip_value = chip_line_led["led"].get_value()
        if not last_chip_value_dict.__contains__(chip_line_led["chip_seq"]):
            last_chip_value_dict[chip_line_led["chip_seq"]] = chip_value

            # 首次进入时，调用code方法
            send_chip_code(chip_value=chip_value, chip_line_led=chip_line_led, sock=sock)
            continue

        if last_chip_value_dict[chip_line_led["chip_seq"]] != chip_value:
            last_chip_value_dict[chip_line_led["chip_seq"]] = chip_value

            send_chip_code(chip_value=chip_value, chip_line_led=chip_line_led, sock=sock)


def send_chip_code(chip_value, chip_line_led, sock):
    """
    发送l or r code
    :param chip_value:
    :param chip_line_led:
    :param sock:
    :return:
    """

    if chip_value == 1:
        chip_code = "L"
        logging.info("Chip: {}, Line: {}, chip_value: {}".format(chip_line_led["chip_seq"],
                                                                str(chip_line_led["chip_line"]),
                                                                str(chip_value)))
        try:
            sock.sendall(bytes(chip_code, 'utf8'))
        except IOError as e:
            logging.error("send_chip_code error: {}".format(e))
            sock.close()


def chip_monitor(sock, addr):
    """
    遍历线口，推送机台状态

    :return:
    """
    logging.info('client info: {}'.format(addr))
    for chip_line_led in get_chip_line_list():

        t = threading.Thread(target=get_chip_value, args=(sock, chip_line_led))
        t.start()


if __name__ == '__main__':
    socket_server()
