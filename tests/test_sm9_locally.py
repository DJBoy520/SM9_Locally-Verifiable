import string

from gmssl import sm9
import SM9_Locally_Varifiable.setup_key as sk_new
import SM9_Locally_Varifiable.message_sign_and_verify as msav
import SM9_Locally_Varifiable.message_aggregate_sign_and_verify as masav
import SM9_Locally_Varifiable.message_aggregate_sign_and_verify_locally as masavl

SUCCESS = True


def test(num):
    import time
    from tqdm import tqdm

    message = 'abc'
    messages1 = list(string.ascii_lowercase)
    messages2 = list(string.ascii_lowercase)
    messages3 = list(string.ascii_lowercase)
    cartesian_product = [item1 + item2 for item1 in messages1 for item2 in messages2]
    cartesian_product = [item1 + item2 for item1 in cartesian_product for item2 in messages3][:num]

    idA = 'a'
    master_public, master_secret = sm9.setup('sign')
    Da = sm9.private_key_extract('sign', master_public, master_secret, idA)

    print("-------------------------------国密SM9签名验签----------------------------------")
    signature = sm9.sign(master_public, Da, message)

    start_time = time.time()
    for _ in tqdm(range(num), desc="Processing"):
        result = sm9.verify(master_public, idA, message, signature)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000
    print(f"签名验证结果:{result}")
    print(f"国密SM9签名验签算法，单独验证{num}条签名执行时间: {execution_time_ms:.2f} 毫秒")

    master_public, master_secret = sk_new.setup('sign')
    Da = sk_new.private_key_extract('sign', master_public, master_secret, idA)
    print("--------------------------------修改后SM9签名验签-----------------------------------")
    signature = msav.sign(master_public, Da, message)

    start_time = time.time()
    for _ in tqdm(range(num), desc="Processing"):
        result = msav.verify(master_public, idA, message, signature)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000

    print(f"签名验证结果:{result}")
    print(f"修改后SM9签名验签算法,单独验证{num}条签名执行时间: {execution_time_ms:.2f} 毫秒")

    print("-------------------------------修改后SM9聚合签名验签---------------------------------")
    start_time = time.time()
    signature = masav.sign_aggregate(master_public, Da, cartesian_product)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(f"修改后SM9聚合签名验签算法，生成{num}条消息的签名执行时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    result = masav.verify_aggregate(master_public, idA, cartesian_product, signature)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000
    print(f"签名验证结果:{result}")
    print(f"修改后SM9聚合签名验签算法，验证{num}条签名执行时间: {execution_time_ms:.2f} 毫秒")

    print("----------------------------修改后SM9聚合签名局部可验证算法----------------------------")
    start_time = time.time()
    signature = masavl.sign_aggregate_locally(master_public, Da, cartesian_product, 0)
    end_time = time.time()
    execution_time_ms = (end_time - start_time) * 1000
    print(
        f"修改后SM9聚合签名局部可验证算法，生成{num}条消息的签名，并针对某条消息生成提示信息执行时间: {execution_time_ms:.2f} 毫秒")

    start_time = time.time()
    result = masavl.verify_aggregate_locally(master_public, idA, cartesian_product[0], signature)
    end_time = time.time()

    execution_time_ms = (end_time - start_time) * 1000
    print(f"签名验证结果:{result}")
    print(f"修改后SM9聚合签名局部可验证算法，选择性验证1条签名执行时间: {execution_time_ms:.2f} 毫秒")
    pass


if __name__ == '__main__':
    test(250)
    test(300)
    test(350)
    test(400)
    test(450)
    test(500)
    test(550)
    test(600)
    test(650)
    test(700)
    test(750)
    test(800)
