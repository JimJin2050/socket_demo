# -*- coding = uft-8 -*-
import configparser


def conf_read(file, section, key=""):
    conf = configparser.ConfigParser()
    conf.read(file, encoding="utf-8")
    if key:
        return conf.get(section, key)
    else:
        key_values = conf.items(section)
        result = {}
        for kv in key_values:
            result[kv[0]] = kv[1]
        return result
