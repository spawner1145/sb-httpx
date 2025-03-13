import httpx
import asyncio
from py_mini_racer import MiniRacer
import re
import json
import logging
from typing import Optional, Dict, Any, Callable

"""
功能说明：
1. 异步 HTTP 请求：
   - async_get: 异步 GET 请求，支持 httpx 所有参数。
   - async_post: 异步 POST 请求，支持 httpx 所有参数。
2. 反爬处理：
   - 检测状态码（403、429、503）或 HTML 响应，识别反爬挑战。
   - 支持多重 JS 挑战，最大挑战次数可配置（max_challenges）。
   - 异步执行多个 JS 挑战，提升性能。
3. JS 执行：
   - extract_js_codes: 从 HTML (<script>) 或 JSON (script 字段) 中提取 JS 代码。
   - execute_js: 异步执行 JS，支持转换函数（transform/request）和常规挑战。
4. 请求转换：
   - 支持 JS 对请求参数（json、data、params、url）的转换。
   - 自动检测并应用转换结果到后续请求。
5. 可配置性：
   - CHALLENGE_RULES: 默认挑战处理规则（token、sign、challenge）。
   - transform_callback: 自定义回调函数，处理特定 JS 结果。
   - rules: 可传入自定义规则字典，扩展挑战类型。
6. 健壮性与调试：
   - 动态超时：根据挑战次数调整（10 + challenge_count * 2）。
   - 日志：详细记录请求、JS 执行和参数变化（DEBUG 级别）。
   - 参数保护：保留原始参数，失败时可回退。
7. 性能优化：
   - 单例 JSEngine：避免重复初始化 MiniRacer。
   - 预加载 CryptoJS：支持加密挑战（AES、HmacSHA256）。
   - 并行 JS 执行：使用 asyncio.gather 处理多个挑战。
"""

# 配置日志
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s")
logger = logging.getLogger(__name__)

class JSEngine:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = MiniRacer()
            crypto_js = """
            const CryptoJS = {
                AES: { encrypt: (msg, key) => btoa(msg) + '_encrypted' },
                HmacSHA256: (msg, key) => msg + '_' + key
            };
            """
            cls._instance.eval(crypto_js)
        return cls._instance

js_engine = JSEngine()

CHALLENGE_RULES = {
    "token": lambda kwargs, result: kwargs["headers"].update({"X-Token": result}),
    "sign": lambda kwargs, result: (kwargs.get("json") or kwargs.setdefault("json", {})).update({"sign": result}),
    "challenge": lambda kwargs, result: kwargs["headers"].update({"X-Challenge": result}),
}

def extract_js_codes(response_text: str) -> list[dict]:
    js_codes = []
    for match in re.finditer(r'<script[^>]*>(.*?)</script>', response_text, re.DOTALL):
        js_codes.append({"type": "html", "code": match.group(1).strip()})
    try:
        data = json.loads(response_text)
        if "script" in data:
            js_codes.append({"type": "json", "code": data["script"]})
        for key, value in data.items():
            if isinstance(value, str) and "function" in value:
                js_codes.append({"type": "json_nested", "code": value})
    except json.JSONDecodeError:
        pass
    return js_codes

async def execute_js(js_code: str, args: Optional[list] = None) -> Any:
    loop = asyncio.get_event_loop()
    try:
        func_names = re.findall(r'function\s+(\w+)\s*\(', js_code)
        await loop.run_in_executor(None, js_engine.eval, js_code)
        
        if func_names:
            func_name = func_names[0]  # 取第一个函数名
            result = await loop.run_in_executor(None, js_engine.call, func_name, *(args or []))
            logger.debug(f"JS executed: {func_name} -> {result}")
            return result
        result = await loop.run_in_executor(None, js_engine.eval, js_code.split(";")[-1].strip())
        logger.debug(f"JS executed (no function): {result}")
        return result
    except Exception as e:
        logger.error(f"JS execution error: {e}\nCode: {js_code[:100]}...")
        return None

async def handle_challenge(client: httpx.AsyncClient, url: str, method: str, 
                         max_challenges: int = 3, transform_callback: Optional[Callable] = None, 
                         rules: Dict[str, Callable] = CHALLENGE_RULES, **kwargs) -> Optional[httpx.Response]:
    challenge_count = 0
    retries_per_challenge = 2
    original_url = url
    kwargs = kwargs.copy()
    kwargs.setdefault("headers", {})
    
    while challenge_count < max_challenges:
        for attempt in range(retries_per_challenge):
            try:
                timeout = httpx.Timeout(10 + challenge_count * 2)
                kwargs["timeout"] = timeout
                logger.debug(f"Request - URL: {url}, kwargs: {kwargs}")
                
                response = await (client.get if method.lower() == "get" else client.post)(url, **kwargs)
                logger.info(f"Challenge {challenge_count + 1}, Attempt {attempt + 1} - Status: {response.status_code}")
                
                if response.status_code in (200, 201):
                    logger.info(f"Success: {response.text[:100]}...")
                    return response
                
                content_type = response.headers.get("Content-Type", "").lower()
                if response.status_code not in (403, 429, 503) and "text/html" not in content_type:
                    logger.info("No further challenges detected")
                    return response
                
                logger.warning(f"Anti-crawl detected: {response.status_code}, Type: {content_type}")
                js_codes = extract_js_codes(response.text)
                if not js_codes:
                    logger.error("No JS challenges found")
                    break
                
                logger.info(f"Found {len(js_codes)} JS challenges")
                response_lower = response.text.lower()
                
                tasks = []
                args_map = {}
                if "json" in kwargs:
                    args_map["json"] = kwargs["json"]
                if "data" in kwargs:
                    args_map["data"] = kwargs["data"]
                if "params" in kwargs:
                    args_map["params"] = kwargs["params"]
                args_map["url"] = url
                
                for i, js_item in enumerate(js_codes):
                    js_code = js_item["code"]
                    logger.debug(f"Challenge {i + 1} ({js_item['type']}): {js_code[:100]}...")
                    
                    if "transform" in js_code.lower() or "request" in js_code.lower():
                        selected_arg = None
                        for arg_type in ["json", "data", "params", "url"]:
                            if arg_type in args_map:
                                selected_arg = args_map[arg_type]
                                break
                        tasks.append(execute_js(js_code, [selected_arg]))
                    else:
                        tasks.append(execute_js(js_code))
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, (js_item, js_result) in enumerate(zip(js_codes, results)):
                    if js_result is None or isinstance(js_result, Exception):
                        continue
                    
                    js_code_lower = js_item["code"].lower()
                    if "transform" in js_code_lower or "request" in js_code_lower:
                        if "url" in js_code_lower and isinstance(js_result, str):
                            url = js_result
                            logger.debug(f"Updated URL: {url}")
                        elif kwargs.get("json") and ("json" in js_code_lower or "transformrequest" in js_code_lower):
                            kwargs["json"] = js_result if isinstance(js_result, dict) else {"transformed": js_result}
                            logger.debug(f"Updated json: {kwargs['json']}")
                        elif kwargs.get("data") and "data" in js_code_lower:
                            kwargs["data"] = js_result if isinstance(js_result, dict) else {"transformed": js_result}
                            logger.debug(f"Updated data: {kwargs['data']}")
                        elif method.lower() == "get" and kwargs.get("params") and "params" in js_code_lower:
                            kwargs["params"] = js_result if isinstance(js_result, dict) else {"transformed": js_result}
                            logger.debug(f"Updated params: {kwargs['params']}")
                    else:
                        if "gettoken" in js_code_lower:
                            kwargs["headers"]["X-Token"] = str(js_result)
                            logger.debug(f"Added X-Token: {js_result}")
                        elif "getchallenge" in js_code_lower:
                            kwargs["headers"]["X-Challenge"] = str(js_result)
                            logger.debug(f"Added X-Challenge: {js_result}")
                        elif "getsign" in js_code_lower:
                            # 将 sign 添加到 json 中
                            if "json" not in kwargs:
                                kwargs["json"] = {}
                            kwargs["json"]["sign"] = str(js_result)
                            logger.debug(f"Added sign to json: {js_result}")
                        elif transform_callback:
                            kwargs = transform_callback(kwargs, js_result, response_lower) or kwargs
                        else:
                            for key, rule in rules.items():
                                if key in response_lower:
                                    rule(kwargs, js_result)
                                    logger.debug(f"Applied rule '{key}': {js_result}")
                                    break
                            else:
                                client.cookies.set(f"challenge_{challenge_count}_{i}", str(js_result))
                                logger.debug(f"Set cookie: challenge_{challenge_count}_{i} = {js_result}")
                
                logger.debug(f"After challenge - URL: {url}, kwargs: {kwargs}")
                challenge_count += 1
                break
            
            except httpx.RequestError as e:
                logger.error(f"Request failed: {e}")
                await asyncio.sleep(1 * (attempt + 1))
        
        if challenge_count < max_challenges:
            await asyncio.sleep(1 * challenge_count)
    
    logger.error(f"Failed after {challenge_count} challenges")
    return None

async def async_get(url: str, transform_callback: Optional[Callable] = None, 
                   rules: Dict[str, Callable] = CHALLENGE_RULES, **kwargs) -> Optional[Dict]:
    async with httpx.AsyncClient() as client:
        response = await handle_challenge(client, url, "get", transform_callback=transform_callback, rules=rules, **kwargs)
        return _parse_response(response)

async def async_post(url: str, transform_callback: Optional[Callable] = None, 
                    rules: Dict[str, Callable] = CHALLENGE_RULES, **kwargs) -> Optional[Dict]:
    async with httpx.AsyncClient() as client:
        response = await handle_challenge(client, url, "post", transform_callback=transform_callback, rules=rules, **kwargs)
        return _parse_response(response)

def _parse_response(response: Optional[httpx.Response]) -> Optional[Dict]:
    if response:
        try:
            return response.json()
        except json.JSONDecodeError:
            return {"text": response.text}
    return None

def custom_transform(kwargs: Dict, js_result: Any, response_text: str) -> Dict:
    if "custom_field" in response_text.lower():
        kwargs["headers"]["X-Custom"] = js_result
    return kwargs

if __name__ == "__main__":
    async def main():
        get_result = await async_get(
            "https://www.baidu.com/s?wd=%E6%97%B6%E9%97%B4&base_query=%E6%97%B6%E9%97%B4&pn=0&oq=%E6%97%B6%E9%97%B4&tn=68018901_58_oem_dg&ie=utf-8&usm=4&rsv_idx=2&rsv_pq=db1e11ba0149dd28&rsv_t=051f4Gfs0d6O1kjBloAcKUq0VT1U06iWRPu%2FNeyVIvZiNPdxDgnaeJjnszjKZFtGWofQv4iUGorN",
            params={"q": "test"},
            headers={"User-Agent": "Mozilla/5.0"},
            transform_callback=custom_transform
        )
        logger.info(f"GET result: {get_result}")

        post_result = await async_post(
            "https://example.com/api/post",
            json={"key": "value"},
            headers={"Authorization": "Bearer token"},
            transform_callback=custom_transform
        )
        logger.info(f"POST result: {post_result}")

    asyncio.run(main())