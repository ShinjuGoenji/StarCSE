import base64
from io import BytesIO
import json
import zipfile
from fastapi import FastAPI, Form, Request, UploadFile, File, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.templating import Jinja2Templates
from typing import List
import shutil
import os
from sqlalchemy import Tuple, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import Base, engine
from auth import router as auth_router

import kms
from models import User, get_db

#################################################
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

#################################################

# FastAPI app init
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# File paths
BASE_UPLOAD_FOLDER = "uploads"
ENCRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "encrypt")
DECRYPT_FOLDER = os.path.join(BASE_UPLOAD_FOLDER, "decrypt")
os.makedirs(ENCRYPT_FOLDER, exist_ok=True)
os.makedirs(DECRYPT_FOLDER, exist_ok=True)

# Register auth router
app.include_router(auth_router)


# Create tables
@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


def extract_user_keys(user_key_id: str) -> bytes:
    with open(f"user_keys/user_sk/{user_key_id}.json", "r") as f:
        user_sk_json = json.load(f)

    try:
        key_material = None
        for item in user_sk_json["value"]:
            for subitem in item["value"]:
                if subitem["tag"] == "KeyValue":
                    for kv in subitem["value"]:
                        if kv["tag"] == "KeyMaterial":
                            key_material = kv["value"]
                            break

        if key_material:
            user_sk = bytes.fromhex(key_material)
    except:
        return None

    with open(f"user_keys/user_pk/{user_key_id}_pk.json", "r") as f:
        user_pk_json = json.load(f)

    try:
        key_material = None
        for item in user_pk_json["value"]:
            for subitem in item["value"]:
                if subitem["tag"] == "KeyValue":
                    for kv in subitem["value"]:
                        if kv["tag"] == "KeyMaterial":
                            key_material = kv["value"]
                            break

        if key_material:
            user_pk = bytes.fromhex(key_material)
    except:
        return None

    return user_pk, user_sk


async def get_user_keys(
    username: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Username not found")
    user_key_id = user.user_key_id
    user_pk, user_sk = extract_user_keys(user_key_id)

    return user_pk, user_sk


async def encrypt_files_with_AES(files: List[UploadFile], AES_key: bytes):
    encrypted_files = []
    for file in files:
        content = await file.read()

        # AES-GCM 加密
        nonce = os.urandom(12)
        aesgcm = AESGCM(AES_key)
        encrypted = aesgcm.encrypt(nonce, content, associated_data=None)
        encrypted_data = nonce + encrypted

        # 加密檔案命名：原檔名 + .enc
        filename = file.filename + ".enc"

        encrypted_files.append({"filename": filename, "content": encrypted_data})

    return encrypted_files


def sign_encrypted_files(
    user_sk: bytes,
    encrypted_files: list,
) -> list:
    private_key = load_der_private_key(user_sk, password=None)

    signatures = []

    for file in encrypted_files:
        encrypted_data = file["content"]
        filename = file["filename"]

        signature = private_key.sign(
            encrypted_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        # 儲存 filename 與對應簽章 (base64 編碼可讀性更好)
        signatures.append(
            {
                "filename": filename,
                "signature": base64.b64encode(signature).decode("utf-8"),
            }
        )

    return signatures


def encrypt_AES_key(AES_key: bytes, user_pk: bytes) -> bytes:
    # public_key = serialization.load_pem_public_key(user_pk, backend=default_backend())
    public_key = serialization.load_der_public_key(user_pk, backend=default_backend())

    AES_key_enc = public_key.encrypt(
        AES_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return AES_key_enc


@app.post("/api/encrypt")
async def encrypt_files(
    username: str = Form(...),
    files: List[UploadFile] = File(...),
):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    # 1. generate AES key
    AES_key: bytes = kms.generate_AES_key()

    # 2. encrypt files with AES key
    encrypted_files: List[bytes] = await encrypt_files_with_AES(
        files=files, AES_key=AES_key
    )

    # 3. get user public and private keys
    # user_pk, user_sk = await get_user_keys(username=username)
    user_pk = "3082020A0282020100A473B330E91FF8C9BC9EB8459037546A888EE7A25912C9CA40771D4D97DFB3BE6DE4115FD4C441B6B9AD9CCB7122BDF252683E2ED2BB27639E6826576EC7D0CAC9E0B2BEEB161EB4FEF16932446B5D9F62A254CE705F4B0A89A7485B073C613C2C1827D77F1B67FA703D5186937CECF2D0AB2D721873A7418973E46AAA928E643DA0C8BE8B95D97D2252CFBD18D4800910E90215BF6429B2684BFF7544AA961CDA62FBC6C3C2455A25EB18F6B1F4D23F940973D802A8BEF67C2F72D46B5BB87492B0653712F79911CE01C439E0C342ACA0D970FFF5876968AC0A05350E50B6626E70856692948901F58C16412438AF76D95511BF4FC6A54D8D2FC4E1A4D742961FAAE1F58D6C097AE4FB19C3396113C26CD4ABA3208302E3D8F40EC19EAA4EC3C7CD47336253721021118B3F42EBBCF063B7556FC2671CA3FAB7EE8C299190635C66CA150A8788AC042725F6ED510AA6AC23023384EF40A3A4C77453960764D1AFDB89D2506FD4DA38A585E3B9A099DFD2E113436A69A36A795FD69617D6C88523880A0EC18C85C36BDC9AE5BED8A2DA56DB455BD0A8476EFED9A684257ABA4A6A7BB253102E7B5EB53E00D81C6BB3B6207F1347129501152E1EE4C3129D3F07E04F506D846D4CF9677E23183FCD35AF512A3C1F1059CEFD8AA52263896045F18BD2CAF0E7664A4C41EFAD24EEF2276224DE0BB28C9041FC2C883B776109E03B0203010001"
    user_sk = "308209280201000282020100A473B330E91FF8C9BC9EB8459037546A888EE7A25912C9CA40771D4D97DFB3BE6DE4115FD4C441B6B9AD9CCB7122BDF252683E2ED2BB27639E6826576EC7D0CAC9E0B2BEEB161EB4FEF16932446B5D9F62A254CE705F4B0A89A7485B073C613C2C1827D77F1B67FA703D5186937CECF2D0AB2D721873A7418973E46AAA928E643DA0C8BE8B95D97D2252CFBD18D4800910E90215BF6429B2684BFF7544AA961CDA62FBC6C3C2455A25EB18F6B1F4D23F940973D802A8BEF67C2F72D46B5BB87492B0653712F79911CE01C439E0C342ACA0D970FFF5876968AC0A05350E50B6626E70856692948901F58C16412438AF76D95511BF4FC6A54D8D2FC4E1A4D742961FAAE1F58D6C097AE4FB19C3396113C26CD4ABA3208302E3D8F40EC19EAA4EC3C7CD47336253721021118B3F42EBBCF063B7556FC2671CA3FAB7EE8C299190635C66CA150A8788AC042725F6ED510AA6AC23023384EF40A3A4C77453960764D1AFDB89D2506FD4DA38A585E3B9A099DFD2E113436A69A36A795FD69617D6C88523880A0EC18C85C36BDC9AE5BED8A2DA56DB455BD0A8476EFED9A684257ABA4A6A7BB253102E7B5EB53E00D81C6BB3B6207F1347129501152E1EE4C3129D3F07E04F506D846D4CF9677E23183FCD35AF512A3C1F1059CEFD8AA52263896045F18BD2CAF0E7664A4C41EFAD24EEF2276224DE0BB28C9041FC2C883B776109E03B02030100010282020034C7835FB3BA54A51E79CC475B313ED11031D92AB42EC0FFBDEFDCC23DF7885F1A32C3D6BF591B841314A2C9726E858AE3A2DC2E37E8E40BE757A2D295D5E06F6D1A4613DB2C56BF9D410A939CFCDE67DC869FF43F817DFA8C5259790999F9D50F8BD321A904393B59D17C3C5652965399E00E6E5B65A6ECF439F339BEB3D9AA5753268A6D0F3365A361F3954B864BEF5CF3837D4A5751C09613AA11CF6F764D1D53FE5D7D0F7925A51CCE7EC27F8208F0B095F2E26B991A4FA204D722FBA578186A2F99DCE70543FF1B7708625818AA81D7379A968916AE06E51265C449E837301DC1DAB9399DBD38BAF49B848E02D6808AFA6EADA2620441476F074259E9DEF3E218B0922C4BA59723474B04740CC9F1B1E44A4055D816994A0C66072044F75481D3BE0D0B921BA3624F1B1282CBA57F955CB7F5EA9E57782D1A91A291C3267AB10F5EB2F86DA1AA394A8540FEDB96695CC654E4573453CAE0FDC81EBC484800E339FD77C5BF3C967591A4C6D5C2EC51768E38A8C14C0795F146D4F0692C4AFB0D2905D110202BAD15BBF72C71C81D84DB5223CA11C13229D1938B4377A79BA19CF2C5894230B0A1E779A7C0028AEE4930214C3C35A184D7687367ED7C422EBD92FF9E729C7FE08CAF3398C9A67A8EFE26A6DDE4E6E1996298B0F264B6961B860833F8CC9914A7BCE0C5E6BFDBFA0903A7BD33CA88890DF7CF3BB94EA57AE90282010100D0E5CB990D315A1627F065AE1787C394448ACEF295051FC17DFC55D3789BB71BB2A68690DC9BC5BB9DC7C076DCEF2E8677343E6B222D0291F7670E300AC275254B7F2B3A05EE5EDB46B8DA13A04BA4F9D1C80338A206A35212A7503781A3CED5D443430809B13B25B5BD87656C2883A586367C7D2E900F38A1B6C3C35419AE272F45789F3F6A0A14D70CB2910106441241DA5BD2AD19D7A41DDA649BA16D8544356BE5945CED452C8C235B4FA6445F746D3A06BC31EE9DD412EA7A795E95C2038B708E16FE50C53FA85E355CCE0093D82427CF66A8E1D34860A5372905ABC895EA3A05EB4F13EDDE90EB94C28C6ED17B090B1A6F1A3759F0AC27D8BD57B2E0B90282010100C9885D7351353DA359581B2C85A1EB757187A60D4FA9EABF75FC521D43358B75BFE1070BC1832D71BC541D017F5BD5E59C06CB9D4ABC893407E5BE665169544F4273E29A4386F763B9BCCA6C7C9D5A12AA1B6B09EBEEAC75A003EEC337F11DE9AF312711EB08712EFF9F0571E68B4706D13911366D4A0F73D402C3CB4218E696E5F9BF6C993187A1592693B99AAA8BB9C35CAE9D3FC007D0ED7FFC8136BC657DF4A539AD150D72E52A50551A9C101B82DB4A0880DAC5E0A73122292E27C615C9BFC402C8CEAD0B1C900B43CCCC25E149E2B0F38E8E8A5FAA5455F62E76929D1C6382694CFBC76CE13FCB6945DD66C706DC54A0772BBA11226729657A14428693028201000CF5D4D5E00DA9CB2A1B2E13C8FDF15267963D14ABCE2F942F9ED22C5695429D034E7596D3390EE17EFE7FA06040AEA0451106B65ADE74045E5714784292A1F5F86321696E28C5D5D0E3731438A3B8CE8F075BBBCDC19FAC5DDFE7882A10E1AA3E8B15C38FE661070BE98056F888E2F2080BA55996E3F52DCC4AAC8697D72808E253EB11E63B4BF8D306C4A55E6CE71842E1AB44BCDC9796650BC1A62E33BF4AE60D95A6C8C527BF85CA43C60348C6AB5083831B75F599F1286347C9F3E652AD299F88114121FDBADF5548F64309A2228CCBB3806905E9B7D9D7263EF34D1F1ABDF76F9A93C366C4A2351B7B9E7ED99C4A8957D080CDE2549E39B2A6BCA42A710282010100A0F291C74DBC9A4C414716F4988876D5E56432DE00982FCCD63A3B8DF925E30997C2EBF09C8BD99832926E53CAD599DE749C0CB2C2840D830B2794C67C100570031F2F828999592B40A3A079C18F9CE6B9098A9372E3BAC179988A6F47D6FD4FAA4533F1A065AE969D38EF8D465446D60FF36666B4236871D5889BBB513F37B09D5BB65FD17C77D808ADC15E8241DFB2EC6DB15A0E169B6764B549001CA99AD85BB0347EA1088B90AF1956CE1882D8A5C9E1B726C9112CD7F96A51BEF5AEC1A9CCC78A7DBA69022DBE6FF0A6B7072D83E751F041125F3A057AB2E817B54463CACF41D03CD5FB2F5E38A7879C6F33EC90F31776CB959554A7C8018C745187CB97028201004A70B3E63D4C602741847DC4B63F6A6F06575858C971DB22A4227FC89F94978CE7A58AF5D3E30FD785071121F907944738FF58CB6EADC910103F28882FC927219B0566B873FAFE1EBE3180EA0FBCF7F8C161F9DDDC855774C118D01055F815274069460C9135EBA821E2458B72984C9DE4F6914D537A3111FB6547A1D753BB270447091E88AE6798BB54AC5DF226056C9CCD8C3FAE61B0052C3813AAA9A3B4E4A5E1984CBB0B8809BB45D8F4721772970DFC607F417A705DDFCD187613A1645545F35045F283398F5EF1CEACE92DEC4DF98B740D6C526CBA8CBEEF2CF8B42B53A16EB8F278121B5DFC24376793F45E2FBD2188B3A09106A6088CACA96BE5C112"
    user_pk = bytes.fromhex(user_pk)
    user_sk = bytes.fromhex(user_sk)

    # 4. sign each encrypted file
    signatures: List[bytes] = sign_encrypted_files(
        user_sk=user_sk, encrypted_files=encrypted_files
    )

    # 5. encrypt AES key using user's public key
    AES_key_enc: bytes = encrypt_AES_key(AES_key, user_pk)

    # 6. TODO: generate certificate

    # --- 建立 ZIP 檔案 ---
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        # 寫入每個加密檔案
        for enc_file in encrypted_files:
            zip_file.writestr(enc_file["filename"], enc_file["content"])

        # 寫入簽章 JSON
        signature_json = json.dumps(signatures, indent=2)
        zip_file.writestr("signatures.json", signature_json)

        # 寫入加密的 AES 金鑰
        zip_file.writestr("aes_key.enc", AES_key_enc)

    zip_buffer.seek(0)

    return StreamingResponse(
        zip_buffer,
        media_type="application/x-zip-compressed",
        headers={"Content-Disposition": "attachment; filename=encrypted_package.zip"},
    )


@app.post("/api/decrypt")
async def decrypt_files(files: List[UploadFile] = File(...)):
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")
    saved_files = []
    for file in files:
        file_location = os.path.join(DECRYPT_FOLDER, file.filename)
        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        saved_files.append(file.filename)
    return {"message": "Decrypted files saved successfully", "files": saved_files}
