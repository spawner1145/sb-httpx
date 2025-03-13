"""
1. 自动检测网页中的反爬机制（支持自定义检测规则）
2. 解析并执行JavaScript挑战代码
3. 自动修正请求参数（headers/params/data）
4. 支持多级挑战处理（指数退避重试机制）
5. 提供简洁的API接口（async_get/async_post）

使用方法：

1. 基础用法：
   --------------------------------------------------
   import asyncio
   from anti_scraping import async_get, async_post

   async def main():
       # GET请求
       response = await async_get("https://example.com/protected")
       # POST请求
       response = await async_post("https://example.com/api", json={"query": "test"})
   
   asyncio.run(main())
   --------------------------------------------------

2. 自定义反爬检测规则：
   --------------------------------------------------
   def custom_anti_check(response: httpx.Response) -> bool:
       # 检测特定文本内容
       return "anti-bot" in response.text.lower()

   async def main():
       response = await async_get(
           "https://example.com",
           anti_scraping_check=custom_anti_check  # 注入自定义检测函数
       )
   --------------------------------------------------

3. 扩展挑战处理规则：
   --------------------------------------------------
   from anti_scraping import CHALLENGE_RULES

   # 新增cookie设置规则
   def handle_cookie(kwargs, result):
       kwargs["headers"]["Cookie"] = f"validation={result}"

   CHALLENGE_RULES["cookie_rule"] = handle_cookie

   # 修改后的规则会自动生效
   --------------------------------------------------

4. 响应处理：
   - 成功响应：返回包含JSON数据或文本的字典
   - 请求失败：返回None
   - 自动处理编码问题，优先解析JSON格式

5. 配置选项：
   - max_challenges: 最大挑战重试次数（默认3次）
   - transform_callback: 自定义响应转换函数
   - anti_scraping_check: 自定义反爬检测函数
   - 支持所有httpx请求参数（headers/params/data/json等）

注意事项：
- 依赖环境需要安装py_mini_racer和httpx
- JavaScript执行环境为V8引擎，确保系统支持
- 建议配合代理使用以应对IP封锁
"""

import httpx
import asyncio
from py_mini_racer import MiniRacer
import re
import json
import logging
import hashlib
import time
from typing import Optional, Dict, Any, Callable, List
from functools import partial

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

class JSEngine:
    """JS执行引擎，支持上下文保持"""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = MiniRacer()
            # 加密模拟环境
            crypto_js = """
            const CryptoJS = {
                AES: {
                    encrypt: (msg, key) => btoa(msg) + '_' + key,
                    decrypt: (cipher, key) => atob(cipher.split('_')[0])
                },
                HmacSHA256: (msg, key) => msg + '_' + key,
                enc: {
                    Base64: {
                        stringify: (data) => btoa(data),
                        parse: (data) => atob(data)
                    },
                    Utf8: {
                        parse: (data) => decodeURIComponent(escape(data)),
                        stringify: (data) => unescape(encodeURIComponent(data))
                    }
                }
            };
            """
            cls._instance.eval(crypto_js)
            cls._instance.context = {}  # 上下文保持功能
        return cls._instance

    def update_context(self, key, value):
        self.context[key] = value

    def get_context(self, key):
        return self.context.get(key)

js_engine = JSEngine()

CHALLENGE_RULES = {
    "token": lambda kwargs, result: kwargs["headers"].update({"X-Token": result}),
    "sign": lambda kwargs, result: (
        kwargs.setdefault("json", {}).update({
            "sign": hashlib.sha256(f"{result}|{time.time()}".encode()).hexdigest()[:32]
        })
    ),
    "challenge": lambda kwargs, result: kwargs["headers"].update({"X-Challenge": result}),
    "cookie": lambda kwargs, result: kwargs["headers"].update({"Cookie": f"verify={result}"}),
}

def default_anti_scraping_check(response: httpx.Response) -> bool:
    """反爬检测规则"""
    anti_patterns = [
        response.status_code in (403, 429, 503),
        "cf-challenge" in response.text.lower(),
        "cloudflare" in response.headers.get("server", "").lower(),
        re.search(r"window\.location\s*=\s*['\"]/.*__cf_chl_rt_tk=.*['\"]", response.text),
        "var s,t,o,p,b,r,e,a,k,i,n,g,f" in response.text
    ]
    return any(anti_patterns)

def extract_js_codes(response_text: str) -> List[dict]:
    """JS代码提取方法"""
    js_codes = []
    
    # HTML内嵌脚本提取
    html_scripts = re.findall(
        r'<script[^>]*>(?://<!\[CDATA\[)?(.*?)(?://\]\]>)?</script>',
        response_text,
        re.DOTALL | re.IGNORECASE
    )
    for script in html_scripts:
        js_codes.append({"type": "html", "code": script.strip()})

    # JSON格式脚本提取
    try:
        data = json.loads(response_text)
        if isinstance(data, dict):
            if "script" in data:
                js_codes.append({"type": "json", "code": data["script"]})
            
            stack = [data]
            while stack:
                current = stack.pop()
                if isinstance(current, dict):
                    for k, v in current.items():
                        if isinstance(v, str) and "function" in v:
                            js_codes.append({"type": "json_nested", "code": v})
                        elif isinstance(v, (dict, list)):
                            stack.append(v)
                elif isinstance(current, list):
                    stack.extend(current)
    except json.JSONDecodeError:
        pass

    return js_codes

async def execute_js(js_code: str, args: Optional[list] = None) -> Any:
    """JS执行方法，支持上下文保持"""
    loop = asyncio.get_event_loop()
    try:
        # 函数定义检测
        func_match = re.search(
            r'function\s+([a-zA-Z_$][\w$]*)\s*\(([^)]*)\)\s*{',
            js_code
        )
        
        if func_match:
            func_name = func_match.group(1)
            params = [p.strip() for p in func_match.group(2).split(',')]
            await loop.run_in_executor(None, js_engine.eval, js_code)
            
            # 参数处理
            exec_args = []
            for param in params:
                if param == "data" and args:
                    if isinstance(args[0], (dict, list)):
                        exec_args.append(json.dumps(args[0]))
                    else:
                        exec_args.append(str(args[0]))
                elif param == "key":
                    exec_args.append("secret_key")
                else:
                    exec_args.append("undefined")
            
            result = await loop.run_in_executor(
                None, 
                partial(js_engine.call, func_name, *exec_args)
            )
            logger.debug(f"执行JS函数 {func_name}({params}) => {str(result)[:100]}...")
            return result
        else:
            # 处理立即执行函数
            if re.search(r"\(function\(\){.*}\)\(\)", js_code):
                wrapper = f"var __result = (function() {{ {js_code} }})();"
                await loop.run_in_executor(None, js_engine.eval, wrapper)
                result = await loop.run_in_executor(None, js_engine.eval, "__result")
            else:
                result = await loop.run_in_executor(
                    None,
                    partial(js_engine.eval, js_code.split(";")[-1].strip())
                )
            logger.debug(f"执行JS表达式 => {str(result)[:100]}...")
            return result
    except Exception as e:
        logger.error(f"JS执行失败: {str(e)}")
        return None

async def handle_challenge(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    max_challenges: int = 3,
    transform_callback: Optional[Callable] = None,
    rules: Dict[str, Callable] = CHALLENGE_RULES,
    anti_scraping_check: Callable[[httpx.Response], bool] = default_anti_scraping_check,
    **kwargs
) -> Optional[httpx.Response]:
    """挑战处理流程"""
    challenge_count = 0
    current_url = url
    original_kwargs = kwargs.copy()
    modified_kwargs = kwargs.copy()
    last_response = None

    # 初始化有效载荷
    payload = None
    if method == "POST":
        payload = modified_kwargs.get("json") or modified_kwargs.get("data") or {}
        if isinstance(payload, dict):
            payload = payload.copy()

    while challenge_count <= max_challenges:
        try:
            # 动态超时设置
            timeout = httpx.Timeout(
                10.0 + challenge_count * 5,
                connect=5.0 + challenge_count * 2
            )
            modified_kwargs["timeout"] = timeout
            
            logger.info(f"请求尝试 #{challenge_count} [URL: {current_url}]")
            response = await client.request(method, current_url, **modified_kwargs)
            last_response = response
            logger.debug(f"响应状态: {response.status_code}")

            if not anti_scraping_check(response):
                logger.info("通过反爬检测")
                return response

            if challenge_count >= max_challenges:
                logger.warning("达到最大挑战次数限制")
                return response

            js_codes = extract_js_codes(response.text)
            if not js_codes:
                logger.warning("未检测到有效JS挑战代码")
                return response

            logger.info(f"发现 {len(js_codes)} 个JS代码片段")
            
            # 构建执行参数
            execution_args = {
                "url": current_url,
                "headers": modified_kwargs.get("headers", {}),
                "params": modified_kwargs.get("params", {}),
                "data": modified_kwargs.get("data", {}),
                "json": modified_kwargs.get("json", {})
            } if method == "GET" else payload.copy()

            tasks = []
            for js_item in js_codes:
                code = js_item["code"]
                
                # 参数注入
                if "transformRequest" in code:
                    inject_args = [payload]
                elif "getSign" in code:
                    inject_args = [payload, "secret_key"]
                else:
                    inject_args = [execution_args]
                
                tasks.append(execute_js(code, args=inject_args))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            modification_flag = False
            for js_item, result in zip(js_codes, results):
                if isinstance(result, Exception) or not result:
                    continue

                code = js_item["code"]
                
                # URL修正
                if re.search(r"\b(window\.location|url)\b", code):
                    new_url = str(result).strip()
                    if re.match(r"https?://", new_url):
                        current_url = new_url
                        modification_flag = True
                        logger.info(f"URL更新为: {current_url}")

                # 参数类型处理
                for param in ["params", "data", "json"]:
                    if re.search(rf"\b{param}\b", code):
                        if param == "json" or (isinstance(result, (dict, list)) and param == "data"):
                            modified_kwargs["json"] = result
                            modified_kwargs["headers"]["Content-Type"] = "application/json"
                            if "data" in modified_kwargs:
                                del modified_kwargs["data"]
                            logger.info("自动转换DATA为JSON格式")
                        else:
                            modified_kwargs[param] = result
                        modification_flag = True
                        logger.info(f"{param.upper()}参数已更新（类型自动识别）")

                # 请求头规则应用
                for rule_key in rules:
                    if re.search(rf"(?i){rule_key}", code):
                        rules[rule_key](modified_kwargs, result)
                        modification_flag = True
                        logger.info(f"应用 {rule_key} 规则到请求参数")

                # 自定义回调处理
                if transform_callback:
                    modified_kwargs = transform_callback(modified_kwargs, result, response.text)

            if not modification_flag:
                logger.warning("JS执行未产生有效参数修改")
                return response

            challenge_count += 1
            await asyncio.sleep(min(2 ** challenge_count, 10))

        except (httpx.RequestError, json.JSONDecodeError) as e:
            logger.error(f"请求异常: {str(e)}")
            if challenge_count == 0:
                modified_kwargs = original_kwargs.copy()
                challenge_count += 1
                continue
            break

    return last_response

async def async_request(
    method: str,
    url: str,
    max_challenges: int = 3,
    transform_callback: Optional[Callable] = None,
    anti_scraping_check: Optional[Callable[[httpx.Response], bool]] = None,
    **kwargs
) -> Optional[Dict]:
    async with httpx.AsyncClient(
        http2=True,
        limits=httpx.Limits(max_keepalive_connections=10),
        follow_redirects=True
    ) as client:
        checker = anti_scraping_check or default_anti_scraping_check
        response = await handle_challenge(
            client=client,
            method=method,
            url=url,
            max_challenges=max_challenges,
            transform_callback=transform_callback,
            anti_scraping_check=checker,
            **kwargs
        )
        return _parse_response(response)

async def async_get(url: str, **kwargs) -> Optional[Dict]:
    return await async_request("GET", url, **kwargs)

async def async_post(url: str, **kwargs) -> Optional[Dict]:
    return await async_request("POST", url, **kwargs)

def _parse_response(response: Optional[httpx.Response]) -> Optional[Dict]:
    if not response:
        return None
    try:
        content_type = response.headers.get("content-type", "").lower()
        if "json" in content_type:
            return response.json()
        return {"text": response.text}
    except Exception as e:
        logger.error(f"响应解析失败: {str(e)}")
        return {"text": response.text}

# 使用示例
if __name__ == "__main__":
    async def demo():
        # 基础使用
        print(await async_get("https://httpbin.org/get"))
        
        # 自定义检测规则
        def custom_check(response):
            return "Example Domain" in response.text
        
        print(await async_get(
            "https://example.com",
            anti_scraping_check=custom_check,
            headers={"X-Custom": "test"}
        ))
    
    asyncio.run(demo())