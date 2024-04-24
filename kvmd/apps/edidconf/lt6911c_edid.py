import subprocess
import time


# LT6911C I2C address: 0x2b(0x56)
def lt6911c_i2c_write_byte(addr, data):
    # print("w", hex(addr), hex(data))
    subprocess.run(["i2cset", "-f", "-y", "2", "0x2b", hex(addr), hex(data)])


def lt6911c_i2c_read_byte(addr):
    result = subprocess.run(["i2cget", "-f", "-y", "2", "0x2b", hex(addr)],
                            stdout=subprocess.PIPE)
    data = result.stdout.decode().strip()
    # print("r", hex(addr), data)
    return data


def lt6911c_i2c_open():
    lt6911c_i2c_write_byte(0xff, 0x80)
    lt6911c_i2c_write_byte(0xee, 0x01)


def lt6911c_id_check():
    count = 0
    id_ok = 0
    # open i2c
    lt6911c_i2c_open()
    # reg bank 0xa0
    lt6911c_i2c_write_byte(0xff, 0xa0)
    while count < 3:
        # read chip id
        chip_id_0 = lt6911c_i2c_read_byte(0x00)
        chip_id_1 = lt6911c_i2c_read_byte(0x01)
        # print("chip id:", chip_id_0, chip_id_1)
        if (chip_id_0 == '0x16' and chip_id_1 == '0x05'):
            id_ok += 1
        else:
            break
        count += 1
    if (id_ok == 3):
        return True
    else:
        return False


def lt6911c_edid_read():
    # print("lt6911c_edid_read")
    edid_hex = []
    edid = []
    lt6911c_i2c_open()
    lt6911c_i2c_write_byte(0x5a, 0x86)
    lt6911c_i2c_write_byte(0x5a, 0x82)
    # read 16 times, 16 bytes one time, 256 bytes total
    j = 0
    while j < 16:
        lt6911c_i2c_write_byte(0x5e, 0x6f)
        lt6911c_i2c_write_byte(0x5a, 0xa2)
        lt6911c_i2c_write_byte(0x5a, 0x82)
        lt6911c_i2c_write_byte(0x5b, 0x01)
        lt6911c_i2c_write_byte(0x5c, 0x80)
        # edid address
        lt6911c_i2c_write_byte(0x5d, j * 16)
        lt6911c_i2c_write_byte(0x5a, 0x92)
        lt6911c_i2c_write_byte(0x5a, 0x82)
        lt6911c_i2c_write_byte(0x58, 0x01)
        # read 16 bytes
        i = 0
        while i < 16:
            edid_hex.append(lt6911c_i2c_read_byte(0x5f))
            i += 1
        j += 1
    """
    edid_str = ' '.join(map(str, edid_hex))
    for i in range (0, len(edid_str), 80):
        print(edid_str[i:i+80])
    """
    for e in edid_hex:
        edid.append(int(e, 16))
    # print(edid)
    return edid


def lt6911c_edid_write(edid):
    # print("lt6911c_edid_write")
    lt6911c_i2c_open()
    lt6911c_i2c_write_byte(0x5a, 0x82)
    lt6911c_i2c_write_byte(0x5e, 0xc0)
    lt6911c_i2c_write_byte(0x58, 0x00)
    lt6911c_i2c_write_byte(0x59, 0x51)
    lt6911c_i2c_write_byte(0x5a, 0x92)
    lt6911c_i2c_write_byte(0x5a, 0x82)
    lt6911c_i2c_open()
    lt6911c_i2c_write_byte(0x5a, 0x82)
    lt6911c_i2c_write_byte(0x5a, 0x86)
    lt6911c_i2c_write_byte(0x5a, 0x82)
    lt6911c_i2c_write_byte(0x5b, 0x01)
    lt6911c_i2c_write_byte(0x5c, 0x80)
    lt6911c_i2c_write_byte(0x5d, 0x00)
    lt6911c_i2c_write_byte(0x5a, 0x83)
    lt6911c_i2c_write_byte(0x5a, 0x82)
    # delay 0.5s
    time.sleep(0.5)
    # reg bank 0x90
    lt6911c_i2c_write_byte(0xff, 0x90)
    lt6911c_i2c_read_byte(0x02)
    # t = lt6911c_i2c_read_byte(0x02)
    # print(t)
    lt6911c_i2c_write_byte(0x02, 0xdf)
    lt6911c_i2c_write_byte(0x02, 0xff)
    lt6911c_i2c_write_byte(0xff, 0x80)
    lt6911c_i2c_write_byte(0xff, 0x80)
    lt6911c_i2c_write_byte(0xee, 0x01)
    lt6911c_i2c_write_byte(0x5a, 0x86)
    # write cycle start
    j = 0
    while j < 16:
        lt6911c_i2c_write_byte(0x5a, 0x82)
        lt6911c_i2c_write_byte(0x5a, 0x86)
        lt6911c_i2c_write_byte(0x5a, 0x82)
        lt6911c_i2c_write_byte(0x5e, 0xef)
        lt6911c_i2c_write_byte(0x5a, 0xa2)
        lt6911c_i2c_write_byte(0x5a, 0x82)
        lt6911c_i2c_write_byte(0x58, 0x01)
        # write 16 bytes
        i = 0
        while i < 16:
            lt6911c_i2c_write_byte(0x59, edid[j * 16 + i])
            i += 1
        lt6911c_i2c_write_byte(0x5b, 0x01)
        lt6911c_i2c_write_byte(0x5c, 0x80)
        # edid address
        lt6911c_i2c_write_byte(0x5d, j * 16)
        lt6911c_i2c_write_byte(0x5e, 0xe0)
        lt6911c_i2c_write_byte(0x5a, 0x92)
        j += 1
    lt6911c_i2c_write_byte(0x5a, 0x82)
    lt6911c_i2c_write_byte(0x5a, 0x8a)
    lt6911c_i2c_write_byte(0x5a, 0x82)

    lt6911c_i2c_write_byte(0xff, 0x90)
    lt6911c_i2c_read_byte(0x02)
    lt6911c_i2c_write_byte(0x02, 0xdf)
    lt6911c_i2c_write_byte(0x02, 0xff)


def lt6911c_edid_prog(edid):
    print("Programming LT6911C EDID...")
    print("Checking LT6911C chip id...")
    if lt6911c_id_check() == False:
        print("Chip ID error!")
        return 1
    else:
        print("ID OK, Writing LT6911C EDID data...")
        lt6911c_edid_write(edid)
        print("Reading...")
        r_edid = lt6911c_edid_read()
        print("Verifying...")
        if r_edid == edid:
            print("OK")
            return 0
        else:
            print("Failed")
            return 1
