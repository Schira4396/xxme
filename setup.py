
import os
import sys


pack_list = ['requests','scapy','colorama','pyexecjs','beautifulsoup4']

with open('requirements.txt','w',encoding='utf-8') as file:
    for i in pack_list:
        file.write(i + '\n')

with open('os_path.log','w',encoding='utf-8') as data:
    data.write(str(sys.path))


try:
    os.system('pip3 install -r requirements.txt')
except:
    print('请检查网络连接.')
    exit(0)



print('Successfully')