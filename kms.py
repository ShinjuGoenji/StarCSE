import re
import subprocess

KMS_URL = "https://9921-140-113-225-145.ngrok-free.app"


def create_user_symmetric_key_cli(tag: str = "user-key"):
    cmd = [
        "./cosmian",
        "--kms-url",
        KMS_URL,
        "--kms-accept-invalid-certs",
        "kms",
        "sym",
        "keys",
        "create",
        "--tag",
        tag,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        # 從 stdout 抓 UUID (示例格式 "Unique identifier: <uuid>")
        match = re.search(r"Unique identifier:\s*([a-f0-9\-]+)", result.stdout)
        if match:
            key_id = match.group(1)
            print("Created key ID:", key_id)
            return key_id
        else:
            print("Could not find key ID in output.")
            print("Full output:", result.stdout)
            return None
    else:
        print("Command failed:")
        print(result.stderr)
        return None
