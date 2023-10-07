import ttkbootstrap as ttk
import tkinter as tk
from tkinter import *
from ttkbootstrap import StringVar
import time
import threading
# S-DES S-boxes
s_box_0 = [
    [1, 0, 3, 2],
    [3, 2, 1, 0],
    [0, 2, 1, 3],
    [3, 1, 0, 2]
]

s_box_1 = [
    [0, 1, 2, 3],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [2, 1, 0, 3]
]


# Initial permutation
initial_permutation = [1,5,2,0,3,7,4,6]
                    

# Expansion permutation
expansion_permutation = [3,0,1,2,1,2,3,0]

# Inverse initial permutation
inverse_initial_permutation = [3, 0, 2, 4, 6, 1, 7, 5]

# P4 permutation
p4_permutation = [1,3,2,0]

# P10 permutation
p10_permutation = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]

# P8 permutation
p8_permutation = [5, 2, 6, 3, 7, 4, 9, 8]


# Key generation
def generate_round_keys(key):
    key = [key[p] for p in p10_permutation]
    left_half = key[:5]
    right_half = key[5:]

    # Left circular shift
    left_half = left_half[1:] + [left_half[0]]
    right_half = right_half[1:] + [right_half[0]]

    round_key_1 = [left_half[i] for i in [0, 1, 2, 3, 4]] + [right_half[i] for i in [0, 1, 2, 3, 4]]
    round_key_2 = [left_half[i] for i in [3, 4, 0, 1, 2]] + [right_half[i] for i in [3, 4, 0, 1, 2]]

    round_key_1 = [round_key_1[p] for p in p8_permutation]
    round_key_2 = [round_key_2[p] for p in p8_permutation]

    return round_key_1, round_key_2

# Initial permutation
def initial_permute(plaintext):
    return [plaintext[p] for p in initial_permutation]


# Expansion permutation
def expansion(plaintext):
    return [plaintext[p] for p in expansion_permutation]

# Inverse initial permutation
def inverse_initial_permute(ciphertext):
    return [ciphertext[p] for p in inverse_initial_permutation]

# XOR operation
def xor(left, right):
    return [l ^ r for l, r in zip(left, right)]

# S-box substitutioncls
def s_box_substitution(four_bits, s_box):
    row = int(str(four_bits[0]) + str(four_bits[3]), 2)
    col = int(str(four_bits[1]) + str(four_bits[2]), 2)
    return [int(bit) for bit in bin(s_box[row][col])[2:].zfill(2)]


# P4 permutation
def p4(plaintext):
    return [plaintext[p] for p in p4_permutation]

# F function
def f(right_half, round_key):
    expanded = expansion(right_half)
    xor_result = xor(expanded, round_key)
    s_box_output = s_box_substitution(xor_result[:4], s_box_0) + s_box_substitution(xor_result[4:], s_box_1)
    return p4(s_box_output)

# 加密
def sdes_encrypt(plaintext, key):
    round_key_1, round_key_2 = generate_round_keys(key)
    # 初始置换
    plaintext = initial_permute(plaintext)
    left_half, right_half = plaintext[:4], plaintext[4:]

    # 第一轮F函数
    f1_result = f(right_half, round_key_1)

    # 异或操作
    xor_result = xor(left_half, f1_result)

    # 交换左半部分和右半部分
    left_half, right_half = right_half, xor_result

    # 第二轮F函数
    f2_result = f(right_half, round_key_2)

    # 异或操作
    xor_result = xor(left_half, f2_result)

    # 加密结果
    ciphertext = xor_result + right_half

    # 逆初始置换
    ciphertext = inverse_initial_permute(ciphertext)

    return ciphertext

# 解密
def sdes_decrypt(ciphertext, key):
    round_key_1, round_key_2 = generate_round_keys(key)
    # 初始置换
    ciphertext = initial_permute(ciphertext)
    
    left_half, right_half = ciphertext[:4], ciphertext[4:]

    # 第一轮F函数
    f1_result = f(right_half, round_key_2)

    # 异或操作
    xor_result = xor(left_half, f1_result)

    # 交换左半部分和右半部分
    left_half, right_half = right_half, xor_result

    # 第二轮F函数
    f2_result = f(right_half, round_key_1)

    # 异或操作
    xor_result = xor(left_half, f2_result)

    # 加密结果
    plaintext = xor_result + right_half

    # 逆初始置换
    plaintext = inverse_initial_permute(plaintext)

    return plaintext

# 暴力破解攻击以找到密钥
def brute_force_attack1(ciphertext, plaintext):
    start_time = time.time()
    for possible_key in range(1024):  # 尝试所有可能的10位密钥
        key = [int(bit) for bit in f"{possible_key:010b}"]
        decrypted_text = sdes_decrypt(ciphertext, key)
        if decrypted_text == plaintext:
            end_time = time.time()
            elapsed_time = end_time-start_time
            return key,elapsed_time
    return None,None

def string_brute_force_attack(ciphertext, plaintext):
    cipher_list = trans_string_To_asc(ciphertext)
    plain_list = trans_string_To_asc(plaintext)
    return brute_force_attack(cipher_list[0],plain_list[0])

# 多线程暴力破解
def brute_force_attack2(ciphertext, plaintext, start_key, end_key, result_dict,num_threads):
    num_threads = num_threads
    for possible_key in range(start_key, end_key):
        key = [int(bit) for bit in f"{possible_key:010b}"]
        decrypted_text = sdes_decrypt(ciphertext, key)
        if decrypted_text == plaintext:
            result_dict['found_key'] = key
            result_dict['elapsed_time'] = time.time() - start_time
            break

def trans_string_To_asc(input_string):
    # 输入字符串
    input_string = input_string
    # 初始化空列表
    list_ascii = []
    # 遍历字符串中的每个字符
    for char in input_string:
        # 获取字符的ASCII码
        ascii_code = ord(char)
        # 将ASCII码转化为8位二进制串，并且用0填充至8位
        binary_string = format(ascii_code, '08b')
        # 将二进制串转化为一个包含8个整数的列表
        binary_list = [int(bit) for bit in binary_string]
        # 将binary_list添加到list1中
        list_ascii.append(binary_list)
    return list_ascii

def trans_asc_To_string(list_ascii):
    result_string = ""
    # 遍历二维数组中的每个二进制列表
    for binary_list in list_ascii:
        # 将二进制列表转化为字符并添加到结果字符串
        ascii_code = int(''.join(map(str, binary_list)), 2)
        character = chr(ascii_code)
        result_string += character
    return result_string

def encrypt_string(plaintext,key):
    plain_list = trans_string_To_asc(plaintext)
    cipher_list = []
    for plain_char in plain_list:
        cipher_char = sdes_encrypt(plain_char,key)
        cipher_list.append(cipher_char)
    return trans_asc_To_string(cipher_list)

def decrypt_string(ciphertext,key):
    cipher_list = trans_string_To_asc(ciphertext)
    plain_list = []
    for cipher_char in cipher_list:
        plain_char = sdes_decrypt(cipher_char,key)
        plain_list.append(plain_char)
    return trans_asc_To_string(plain_list)


key = []
plaintext = []
ciphertext = []

# button1 得到第一次输入，并对不符合输入规范的操作进行提示
def getText1(input1,l_text,fn):
    if(fn==0 or fn ==1 or fn == 3 or fn == 4):
        if(len(input1.get())!=10):
            text = '输入密钥不符合10位规范'
            l_text.set(text)
            return

        global key
        key = [ int(x) for x in str(input1.get()) ]
        input1.delete(0, "end")
        if(fn==0):
            text = '请输入8位明文。'
        elif(fn==1):
            text = '请输入8位密文。'
        elif(fn==3 or fn == 4):
            text='请输入一个英文字符串'
        l_text.set(text)
        return

# button2 得到第二次输入，调用函数实现最终功能，并展现结果
def getText2(input1,l_text,fn):
    if(fn==0):
        if(len(input1.get())!=8):
            text = '输入明文不符合8位规范'
            l_text.set(text)
            return
        global plaintext
        plaintext = [ int(x) for x in str(input1.get()) ]
        ciphertext1 = sdes_encrypt(plaintext, key)
        str1 = ''.join(str(i) for i in plaintext)
        str2 = ''.join(str(i) for i in ciphertext1)
        text = '明文为：' + str1 + ' 密文为' + str2
        print(text)
        l_text.set(text)
        input1.delete(0, "end")
        return
    elif(fn==1):
        if (len(input1.get()) != 8):
            text = '输入密文不符合8位规范'
            l_text.set(text)
            return
        global ciphertext
        ciphertext = [ int(x) for x in str(input1.get()) ]
        plaintext1 = sdes_decrypt(ciphertext,key)
        str1 = ''.join(str(i) for i in plaintext1)
        str2 = ''.join(str(i) for i in ciphertext)
        text = '明文为：' + str1 + ' 密文为' + str2
        l_text.set(text)
        print(text)
        input1.delete(0, "end")
        return
    elif(fn==3):
        plaintext2 = input1.get()
        if(len(plaintext2)==0):
            text = '输入不能为空'
            l_text.set(text)
            return
        text = encrypt_string(plaintext2,key)
        text = '明文为：' + plaintext2 + ' 密文为：' + text
        l_text.set(text)
    elif (fn == 4):
        ciphertext2 = input1.get()
        if (len(ciphertext2) == 0):
            text = '输入不能为空'
            l_text.set(text)
            return
        text = decrypt_string(ciphertext2, key)
        text = '密文为：' + text + ' 明文为：' + ciphertext2
        l_text.set(text)

# 暴力破解btn
# 单线程btn1
def getT1(input1, input2, l_text):
    if (len(input1.get()) != 8 and len(input2.get())!=8):
        text = '输入不符合8位规范'
        l_text.set(text)
        return
    plaintext3 = [ int(x) for x in str(input1.get()) ]
    ciphertext3 = [ int(x) for x in str(input2.get()) ]
    found_key, elapsed_time = brute_force_attack1(ciphertext3, plaintext3)

    if found_key is not None:
        str1 = ''.join(str(i) for i in found_key)
        text = '找到密钥：'+str1 + '\n' +'破解时间：' + str(elapsed_time) + 's'
        l_text.set(text)
    else:
        text='未找到密钥'
        l_text.set(text)
start_time = 0
# 多线程btn2：
def getT2(input1, input2, input3, l_text):
    if (len(input1.get()) != 8 and len(input2.get())!=8):
        text = '输入不符合8位规范'
        l_text.set(text)
        return
    elif(len(input3.get())==0):
        text = '请输入线程数！'
        l_text.set(text)
        return
    plaintext3 = [int(x) for x in str(input1.get())]
    ciphertext3 = [int(x) for x in str(input2.get())]
    num_threads = int(input3.get())
    keys_per_thread = 1024 // num_threads
    found_key = None
    elapsed_time = None
    result_dict = {'found_key': None, 'elapsed_time': None}
    global start_time
    start_time = time.time()

    # 创建并启动多个线程
    threads = []
    for i in range(num_threads):
        start_key = i * keys_per_thread
        end_key = start_key + keys_per_thread
        thread = threading.Thread(
            brute_force_attack2(ciphertext3, plaintext3, start_key, end_key, result_dict, num_threads))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    found_key = result_dict['found_key']
    elapsed_time = result_dict['elapsed_time']

    if found_key is not None:
        str1 = ''.join(str(i) for i in found_key)
        text = '找到密钥：' + str1 + '\n' + '破解时间：' + str(elapsed_time) + 's'
        l_text.set(text)
    else:
        text = '未找到密钥'
        l_text.set(text)


# 跳转页面
def create(fun) :
    # 定义StringVar
    l_text = StringVar()
    # 初始化数据
    childW1 = Toplevel(frame)  # 创建子窗口
    childW1.geometry("400x400")
    if(fun==0) :
        text = "请输入10位密钥"
        l_text.set(text)
        childW1.title('加密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text,0))
        b2 = ttk.Button(childW1, text="确认明文", command=lambda: getText2(input1, l_text,0))
    elif(fun==1):
        text = "请输入10位密钥"
        l_text.set(text)
        childW1.title('解密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text, 1))
        b2 = ttk.Button(childW1, text="确认密文", command=lambda: getText2(input1, l_text, 1))
    elif(fun==3):
        text = "请输入10位密钥"
        l_text.set(text)
        childW1.title('拓展加密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text, 3))
        b2 = ttk.Button(childW1, text="确认明文", command=lambda: getText2(input1, l_text, 3))
    elif (fun == 4):
        text = "请输入10位密钥"
        l_text.set(text)
        childW1.title('拓展解密')
        b1 = ttk.Button(childW1, text="确认密钥", command=lambda: getText1(input1, l_text, 3))
        b2 = ttk.Button(childW1, text="确认密文", command=lambda: getText2(input1, l_text, 3))
    input1 = ttk.Entry(childW1, bootstyle="info", font=("微软雅黑", 12))
    input1.place(x=100,y=100)
    label = ttk.Label(childW1, textvariable=l_text, font=("微软雅黑", 12))
    label.place(x=100,y=150)
    b1.place(x=90, y=200)
    b2.place(x=250, y=200)

def createT():
    # 定义StringVar
    l_text = StringVar()
    text='请输入8位明文和8位密文'
    l_text.set(text)
    childW3 = Toplevel(frame)  # 创建子窗口
    childW3.geometry("400x400")
    childW3.title('暴力破解')
    label1 = ttk.Label(childW3, text='明文：', font=("微软雅黑", 12))
    label2 = ttk.Label(childW3, text='密文：', font=("微软雅黑", 12))
    label3 = ttk.Label(childW3, textvariable=l_text, font=("微软雅黑", 12))
    label4 = ttk.Label(childW3, text='线程数量：', font=("微软雅黑", 12))
    input1 = ttk.Entry(childW3, bootstyle="info", font=("微软雅黑", 12))
    input2 = ttk.Entry(childW3, bootstyle="info", font=("微软雅黑", 12))
    input3 = ttk.Entry(childW3, bootstyle="info", font=("微软雅黑", 12))
    btn1 = ttk.Button(childW3, text="单线程破解", command=lambda: getT1(input1, input2, l_text))
    btn2 = ttk.Button(childW3, text="多线程破解", command=lambda: getT2(input1, input2, input3, l_text))
    label1.place(x=60,y=55)
    input1.place(x=120,y=50)
    label2.place(x=60,y=115)
    input2.place(x=120,y=110)
    label3.place(x=120,y=155)
    btn1.place(x=160,y=210)
    label4.place(x=40,y=250)
    input3.place(x=120,y=250)
    btn2.place(x=160,y=310)

# 创建窗体
win = tk.Tk()
win.title("S-DES")
win.geometry("500x300")
win.resizable(False, False) # 不允许改变窗口大小

# 创建一个容器来包括其他控件
frame = ttk.Frame(win)

frame.pack()

# 标题
title = ttk.Label(frame,text='Encryption & Decryption', font=("bold", 20), bootstyle='primary' )
title.pack(padx=10,pady=20)
# 关卡提示
info = ttk.Label(frame,text='请选择相应关卡',bootstyle='warning', font=15)
info.pack(padx=10,pady=10)
# 按钮
b1 = ttk.Button(frame, text="加密", command=lambda:create(0))
b1.pack(padx=15,pady=10,side='left')

b2 = ttk.Button(frame, text="解密", command=lambda:create(1))
b2.pack(padx=15,pady=10,side='left')

b3 = ttk.Button(frame, text="暴力破解", command=lambda :createT())
b3.pack(padx=15,pady=10,side='left')

b4 = ttk.Button(frame, text="拓展加密", command=lambda:create(3))
b4.pack(padx=15,pady=10,side='left')

b5 = ttk.Button(frame, text="拓展解密", command=lambda:create(4))
b5.pack(padx=15,pady=10,side='left')
frame.mainloop()

