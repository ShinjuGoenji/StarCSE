from cosmian_kms import KmsClient
import asyncio

KMS_URL = "https://9921-140-113-225-145.ngrok-free.app"
KMS_API_KEY = None
INSECURE_MODE = True


async def create_user_symmetric_key(tag: str = "user-key") -> str:
    client = KmsClient(
        server_url=KMS_URL, api_key=KMS_API_KEY, insecure_mode=INSECURE_MODE
    )
    key_id = await client.create_symmetric_key(
        key_len_in_bits=256, algorithm="AES", tags=[tag]
    )
    return key_id


def create_user_symmetric_key_sync(tag: str = "user-key") -> str:
    return asyncio.run(create_user_symmetric_key(tag))
