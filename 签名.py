from ecdsa import SigningKey, VerifyingKey, SECP256k1
def get_multiline_block(prompt="输入内容，最后仅输入 END 结束："):
    """
    多行输入函数，直到输入 END 为止，收集所有内容并返回字符串。
    """
    print(prompt)
    lines = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)
def create_private_key():
    """
    创建新私钥，打印出HEX编码的私钥（不保存到本地！只一次性输出）
    """
    sk = SigningKey.generate(curve=SECP256k1)   # 生成私钥对象，使用secp256k1曲线
    prikey_hex = sk.to_string().hex()           # 转换为HEX字符串
    print("\n=== 请务必抄下你的私钥（HEX编码） ===")
    print(prikey_hex)                           # 输出私钥，用户手抄
    print("私钥只显示一次，请妥善保存！")
    print("=========================================\n")
    return sk                                   # 返回私钥对象
def import_private_key():
    """
    导入私钥，要求输入HEX编码字符串，转为ecdsa的SigningKey对象
    """
    prikey_hex = input("请输入你的私钥（HEX编码）: ").strip()
    try:
        prikey_bytes = bytes.fromhex(prikey_hex)
        sk = SigningKey.from_string(prikey_bytes, curve=SECP256k1)
        print("私钥导入成功。")
        return sk
    except Exception as e:
        print("导入私钥失败:", str(e))
        return None
def get_public_key(sk):
    """
    从已有私钥对象导出公钥，HEX编码形式显示，可公开
    """
    vk = sk.get_verifying_key()        # 获取VerifyingKey对象（公钥）
    pubkey_hex = vk.to_string().hex()  # 转HEX字符串
    print("\n你的公钥（HEX编码，可安全公开）:")
    print(pubkey_hex)
    return vk
def sign_message_to_block(sk, message):
    """
    传入私钥和待签名消息，返回PGP风格的签名区块（包含正文和HEX签名）
    """
    signature = sk.sign(message.encode())             # 用私钥对消息签名，结果为二进制
    block = (
        "-----BEGIN SIGNED MESSAGE-----\n"
        f"{message}\n"
        "-----BEGIN SIGNATURE-----\n"
        f"{signature.hex()}\n"
        "-----END SIGNATURE-----"
    )
    print("\n=== 签名结果如下 请全部复制并妥善保存 ===\n")
    print(block)
    print("\n=== 完成 ===\n")
    return block
def parse_signed_block(block):
    """
    从PGP签名区块中解析出消息和HEX签名
    参数block: 多行字符串，包括所有区块头
    返回值: (message, signature-hex)
    """
    lines = block.splitlines()
    try:
        start_message = lines.index("-----BEGIN SIGNED MESSAGE-----") + 1  # 消息正文起始行
        start_sig = lines.index("-----BEGIN SIGNATURE-----")                # 签名起始行
        end_sig = lines.index("-----END SIGNATURE-----")                    # 签名结束行
        message_lines = lines[start_message:start_sig]           # 获取消息正文多行
        message = "\n".join(message_lines)                       # 拼成完整消息
        signature = "\n".join(lines[start_sig+1:end_sig]).strip()# 签名可能有多行都加进来
        return message, signature                                # 返回消息和签名
    except Exception as e:
        print("格式解析失败，请检查 block 格式。错误：", str(e))
        return None, None
def verify_signed_block(vk):
    """
    校验PGP风格签名区块。用户需要粘贴完整签名区块，用END结束
    参数vk: VerifyingKey对象（公钥）
    """
    print("请输入完整signed message block，最后输入 END：")
    block = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        block.append(line)
    block_message = "\n".join(block)
    message, signature_hex = parse_signed_block(block_message)
    if message is None or signature_hex is None:
        print("Block格式有误，无法校验。")
        return
    try:
        # 校验签名
        vk.verify(bytes.fromhex(signature_hex), message.encode())
        print("签名校验：通过")
    except Exception as e:
        print("签名校验：失败", str(e))

def main():
    """
    主菜单逻辑，实现所有功能选择。
    """
    sk = None  # 全局变量，当前使用的私钥
    while True:
        print("\n==== ECDSA PGP-like 工具菜单 ====")
        print("1. 创建新私钥（HEX编码，仅显示一次）")
        print("2. 导入私钥（HEX编码）")
        print("3. 显示当前私钥的公钥（HEX编码）")
        print("4. 生成PGP-like签名块（输入消息，多行，END结束）")
        print("5. 校验PGP-like签名块（输入公钥HEX和完整签名块，多行，END结束）")
        print("0. 退出")
        choice = input("请输入您的选择： ").strip()

        if choice == '1':
            sk = create_private_key()
        elif choice == '2':
            sk = import_private_key()
        elif choice == '3':
            if not sk:
                print("请先创建或导入私钥。")
                continue
            get_public_key(sk)
        elif choice == '4':
            if not sk:
                print("请先创建或导入私钥。")
                continue
            message = get_multiline_block("请输入要签名的消息（支持多行）。完成后输入 END：")
            sign_message_to_block(sk, message)
        elif choice == '5':
            pubkey_hex = input("请输入公钥（HEX编码）：").strip()
            try:
                vk = VerifyingKey.from_string(bytes.fromhex(pubkey_hex), curve=SECP256k1)
            except Exception as e:
                print("公钥格式有误：", str(e))
                continue
            verify_signed_block(vk)
        elif choice == '0':
            print("再见!")
            break
        else:
            print("无效选项，请重试。")
if __name__ == "__main__":
    main()
