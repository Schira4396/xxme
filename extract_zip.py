import zipfile
import my_word


def extract_zip(arg):
    filename = arg[0]
    password_txt = arg[1]

    ls1 = open(password_txt, 'r', encoding='utf-8').readlines()
    print(ls1)
    pwd_list = []
    for i in ls1:
        pwd_list.append(i.rstrip('\n'))
    file = zipfile.ZipFile(filename)
    print('start blasting...')
    print(pwd_list)
    for i in pwd_list:
        try:
            file.extractall(pwd=i.encode('utf-8'))
            print('[' + my_word.UseStyle('+', fore='green') + ']' + ' OK. key is \'' + str(i) + '\'')
            break
        except:
            print('[' + my_word.UseStyle('+', fore='red') + ']' + 'test ' + str(i))


