from cosmian_kms import KMS
import uuid

# Ngrok 公開的 KMS URL
KMS_URL = "https://9921-140-113-225-145.ngrok-free.app"


# 建立 KMS 対稱金鑰，並回傳金鑰 ID
def create_user_symmetric_key() -> str:
    try:
        key_tag = f"user-sk-{uuid.uuid4()}"
        kms = KMS(url=KMS_URL, verify_tls=False)  # 忽略 Ngrok 測試憑證
        key_id = kms.create_symmetric_key(tag=key_tag)
        return key_id
    except Exception as e:
        raise RuntimeError(f"Failed to create KMS key: {str(e)}")
