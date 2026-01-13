import hashlib
import base64
import os
import secrets
import requests
import webbrowser
from urllib.parse import urlparse, parse_qs, urlencode,unquote


# --- 1. 配置参数 (根据你的服务修改) ---
CLIENT_ID = "1"
REDIRECT_URI = "http://100.64.0.1:8082/auth/"  # 确保在服务端已注册
AUTH_ENDPOINT = "http://100.64.0.1:8084/oauth/authorize"
TOKEN_ENDPOINT = "http://100.64.0.1:8084/oauth/token"
SCOPE = "w+"

# --- 2. 生成 PKCE 参数 (OAuth 2.1 核心要求) ---
def generate_pkce():
    # Code Verifier: 随机字符串 (43-128字符)
    verifier = secrets.token_urlsafe(64)

    # Code Challenge: SHA256 哈希后进行 Base64 编码
    sha256_hash = hashlib.sha256(verifier.encode('utf-8')).digest()
    challenge = base64.urlsafe_b64encode(sha256_hash).decode('utf-8').replace('=', '')

    return verifier, challenge

def test_oauth_21_flow():
    code_verifier, code_challenge = generate_pkce()
    state = secrets.token_urlsafe(16)

    # --- 3. 构造授权 URL ---
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"  # OAuth 2.1 必须使用 S256
    }
    auth_url = f"{AUTH_ENDPOINT}?{urlencode(params)}"

    print(f"请在浏览器中打开此 URL 并授权:\n{auth_url}\n")
    webbrowser.open(auth_url)

    # --- 4. 模拟回调获取授权码 ---
    # 实际应用中，这里需要一个 Web Server (如 Flask) 来接收回调
    # 测试时，手动复制浏览器地址栏中的 'code' 参数
    full_callback_url = input("授权后，请复制浏览器跳转后的完整 URL 并粘贴在此: ")

    from urllib.parse import urlparse, parse_qs
    query_params = parse_qs(urlparse(full_callback_url).query)
    auth_code = query_params.get("code", [None])[0]

    if not auth_code:
        print("未获取到授权码，请检查 URL。")
        return

    # --- 5. 换取 Access Token ---
    print("\n正在请求 Access Token...")
    token_data = {
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": code_verifier  # 必须提供 Verifier 供服务端校验
    }

    response = requests.post(TOKEN_ENDPOINT, data=token_data)

    if response.status_code == 200:
        token_info = response.json()
        print("成功获取 Token!")
        print(f"Access Token: {token_info.get('access_token')}")
    else:
        print(f"Token 请求失败: {response.status_code}")
        print(response.text)

def test_automated_oauth_21():
    client = requests.Session() # 使用 Session 自动管理 Cookie
    code_verifier, code_challenge = generate_pkce()
    auth_params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPE,
        "code_challenge": code_challenge,
        "user_id":"e76fa28b-b3da-4ef1-bb8a-150151af752e",
        "code_challenge_method": "S256"
    }
    login_data = {
        "username": "toms",
        "password": "v12345"
    }
    # print("正在模拟登录...")
    # client.post("http://100.64.0.1:8084/auth/login", data=login_data)

    # 4. 请求授权地址 (allow_redirects=False 非常重要)
    # 因为我们不需要真的跳转到 localhost，只需要拿到 Location 里的 code
    print("发送授权请求...")
    response = client.get(AUTH_ENDPOINT, params=auth_params, allow_redirects=False)
    # 5. 从重定向 Header 中提取 Authorization Code
    # 正常流程会返回 302 Redirect 到 REDIRECT_URI?code=xxx
    location = response.headers.get("Location")
    if not location:
        print("未发现重定向，可能需要登录或参数错误。内容：", response.text)
        return

    query = parse_qs(urlparse(location).query)
    auth_code = query.get("code", [None])[0]

    if auth_code:
        print(f"自动抓取到 Code: {auth_code}")

        # 6. 换取 Token (同之前)
        token_data = {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": auth_code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": code_verifier
        }
        token_res = requests.post(TOKEN_ENDPOINT, data=token_data)
        print("Token 结果:", token_res.json())
    else:
        print("location: ", query)

if __name__ == "__main__":
    test_automated_oauth_21()
