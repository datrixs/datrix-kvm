import gpiod


class ControlManager:

    def __init__(self):

        # todo chip和line需要按照真实线口修改
        L_OR_R_BUTTON_CHIP = "gpiochip0"
        self.L_OR_R_BUTTON_LINE_OFFSET = 14

        chip = gpiod.Chip(L_OR_R_BUTTON_CHIP)
        self.button_chip_line = chip.get_line(self.L_OR_R_BUTTON_LINE_OFFSET)

        # true（允许本地控制） or false（不允许本地控制）
        self.local_permission = True

        # get操作类型为in，set操作类型为out
        self.button_chip_line.request(consumer=str(self.L_OR_R_BUTTON_LINE_OFFSET), type=gpiod.LINE_REQ_DIR_IN)

    def get_l_or_r_value(self):
        """
        获取当前线口value
        1.默认状态=R，开关按下去=L
        2.线口默认状态code是0，按下去的时候是1
        :return:
        """

        l_or_r_value = "R"
        button_chip_line_value = self.button_chip_line.get_value()
        if button_chip_line_value == 1:
            l_or_r_value = "L"
        return l_or_r_value

    def set_local_permission(self, enable: bool):
        """
        设置本地鼠标键盘操作权限
        :param enable: true（允许本地控制） or false（不允许本地控制）
        :return:
        """

        # 保存状态到本地
        self.local_permission = enable

    def get_remote_permission(self):
        """
        获取远程鼠标键盘操作权限
            1.默认R，查看视频，远程操作
            2.L时，只允许查看视频，不允许远程操作
        :return: bool true（允许控制） or false（不允许控制）
        """

        l_or_r_value = self.get_l_or_r_value()
        if l_or_r_value == "L":
            return False
        else:
            return True
