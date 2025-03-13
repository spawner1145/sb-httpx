from anti_scraping import async_get, async_post
import asyncio

async def test_requests():
    get_result = await async_get(
        "https://www.baidu.com/s?wd=%E6%97%B6%E9%97%B4&base_query=%E6%97%B6%E9%97%B4&pn=0&oq=%E6%97%B6%E9%97%B4&tn=68018901_58_oem_dg&ie=utf-8&usm=4&rsv_idx=2&rsv_pq=db1e11ba0149dd28&rsv_t=051f4Gfs0d6O1kjBloAcKUq0VT1U06iWRPu%2FNeyVIvZiNPdxDgnaeJjnszjKZFtGWofQv4iUGorN",
        params={"q": "test"},
        headers={"User-Agent": "Mozilla/5.0"}
    )
    print(f"GET result: {get_result}")
    
asyncio.run(test_requests())