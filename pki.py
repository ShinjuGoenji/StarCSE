# import re
# import subprocess

# CMD = [
#     "./cosmian",
#     "--kms-url",
#     "https://9921-140-113-225-145.ngrok-free.app",
#     "--kms-accept-invalid-certs",
#     "kms",
# ]


# def export_file(export_cmd: list):
#     cmd = CMD + export_cmd
#     result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

#     if result.returncode == 0:
#         return True
#     else:
#         return False


# def create_root_ca():
#     cmd = CMD + [
#         "certificates",
#         "certify",
#         "--generate-key-pair",
#         "--algorithm",
#         "rsa2048",
#         "--subject-name",
#         "CN=StarCSE Root CA,O=StarCSE,C=TW",
#         "--days",
#         "365",
#         "--tag",
#         "root-ca",
#     ]
#     result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

#     if result.returncode == 0:
#         print(result.stdout)  # 可視需求保留印出
#         # 抓 UUID
#         match = re.search(r"Unique identifier:\s*([a-f0-9\-]+)", result.stdout)
#         if match:
#             cert_id = match.group(1)
#             export_cmd = [
#                 "certificates",
#                 "export",
#                 "--certificate-id",
#                 cert_id,
#                 f"root_ca/{cert_id}.json",
#             ]
#             if not export_file(export_cmd):
#                 return None
#             return cert_id
#         else:
#             return None
#     else:
#         return None


# def create_client_ca(client_id):
#     cmd = CMD + [
#         "certificates",
#         "certify",
#         "--issuer-private-key-id",
#         client_id,
#         "--issuer-ceritficate-id",
#         "07f806a5-71c7-4d39-9e06-e3920b91609d",
#         "--generate-key-pair",
#         "--algorithm",
#         "rsa2048",
#         "--subject-name",
#         "CN=StarCSE Client CA,O=StarCSE,C=TW",
#         "--days",
#         "365",
#         "--tag",
#         "root-ca",
#     ]
#     result = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8")

#     if result.returncode == 0:
#         print(result.stdout)  # 可視需求保留印出
#         # 抓 UUID
#         match = re.search(r"Unique identifier:\s*([a-f0-9\-]+)", result.stdout)
#         if match:
#             cert_id = match.group(1)
#             export_cmd = [
#                 "certificates",
#                 "export",
#                 "--certificate-id",
#                 cert_id,
#                 f"client_ca_cert/{cert_id}.json",
#             ]
#             if export_file(export_cmd):
#                 return cert_id
#             else:
#                 return None
#         else:
#             return None
#     else:
#         return None


# create_root_ca()
