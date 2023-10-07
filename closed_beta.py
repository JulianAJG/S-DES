from DES import sdes_decrypt,trans_string_To_asc,sdes_encrypt


def closed_beta_key(plaintext,ciphertext):
    key_list = []
    print("封闭测试1:",end='\n')
    for possible_key in range(1024):  # 尝试所有可能的10位密钥
        key = [int(bit) for bit in f"{possible_key:010b}"]
        if plaintext == sdes_decrypt(ciphertext,key):
            key_list.append(key)
    print("该明密文对一共有",len(key_list),"个密钥，分别为：")
    print(key_list,end='\n')
    return None

def closed_beta_plaintext(plaintext):
    print("封闭测试2:",end='\n')
    ciphertext_list = []
    has_duplicates = False
    for possible_key in range(1024):
        key = [int(bit) for bit in f"{possible_key:010b}"]
        ciphertext_list.append(sdes_encrypt(plaintext,key))
    
    for i in range(len(ciphertext_list)):
        for j in range(i+1):
            if ciphertext_list[i] ==ciphertext_list[j]:
                has_duplicates = False
                break           
    if has_duplicates:
        print("不同的密钥可能会产生相同的密文")
    else:
        print("不同密钥不可能产生相同的密文") 
            

if __name__ == "__main__":
    plaintext = [1,0,1,1,1,1,1,1]
    ciphertext = [1, 0, 0, 0, 1, 0, 1, 0]
    print("参与测试的明文为：",plaintext)
    print("参与测试的密文为：",ciphertext)
    closed_beta_key(plaintext,ciphertext)
    closed_beta_plaintext(plaintext)