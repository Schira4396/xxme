import requests
import execjs  # 这个库是PyExecJS
import re
from urllib import parse
from bs4 import BeautifulSoup


headers = {
    'User-Agent': 'Mozilla/5.0 '
                  '(Macintosh; Intel Mac OS X 10_11_2)'
                  ' AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/47.0.2526.80 Safari/537.36'
}


ss = requests.session()

def get_htm(name):
    url = 'https://search.douban.com/movie/subject_search?search_text=' + parse.quote(name) + '&cat=1002'
    response = ss.get(url=url, headers=headers)
    r = re.search('window.__DATA__ = "([^"]+)"', response.text).group(1)  # 加密的数据
    # 导入js
    with open('main.js', 'r', encoding='utf-8') as f:
        decrypt_js = f.read()
    ctx = execjs.compile(decrypt_js)
    data = ctx.call('decrypt', r)

    # for item in data['payload']['items']:
    tmp = data['payload']['items'][0]

    return tmp['abstract'], tmp['abstract_2'], tmp['url'],tmp['rating']['value']

def get_flag(url):

    new_page = ss.get(url=url, headers=headers).text  # 详细页面

    html = BeautifulSoup(new_page, "lxml")  # 解析对象

    div = html.find_all('div', class_='indent')  # 查找div

    for i in div:
        span = i.find('span', property='v:summary')
        if span:
            return span.get_text().replace('\n','').strip()










