import asyncio
import logging
from flask import Flask, request, jsonify
from http import HTTPStatus
from threading import Thread
from anti_scraping import async_get, async_post

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - [%(funcName)s] - %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

@app.route("/api/get", methods=["GET"])
def get_challenge():
    # 三级挑战测试
    if "X-Token" not in request.headers:
        return "<script>function getToken() { return 'token_' + Date.now(); }</script>", HTTPStatus.FORBIDDEN
    if "X-Challenge" not in request.headers:
        return "<script>function getChallenge() { return 'challenge_' + Math.random().toString(36).substr(2); }</script>", HTTPStatus.FORBIDDEN
    return jsonify({"status": "success", "method": "GET"}), HTTPStatus.OK

@app.route("/api/post", methods=["POST"])
def post_challenge():
    data = request.get_json() or {}
    # 两级挑战测试
    if "transformed" not in data:
        return "<script>function transformRequest(data) { return { transformed: data.key + '_transformed' }; }</script>", HTTPStatus.FORBIDDEN
    if "sign" not in data:
        return '''<script>
            function getSign(data, key) {
                return CryptoJS.HmacSHA256(JSON.stringify(data), key).toString();
            }
        </script>''', HTTPStatus.FORBIDDEN
    return jsonify({"status": "success", "method": "POST", "data": data}), HTTPStatus.OK

def run_flask():
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)

server_thread = Thread(target=run_flask, daemon=True)
server_thread.start()

async def test_requests():
    try:
        # 测试GET请求
        logger.info("Starting GET test...")
        get_result = await async_get(
            "http://127.0.0.1:5000/api/get",
            params={"q": "test"},
            headers={"User-Agent": "Mozilla/5.0"}
        )
        logger.info(f"GET result: {get_result}")
        assert get_result and get_result.get("status") == "success", "GET测试失败"

        # 测试POST请求
        logger.info("Starting POST test...")
        post_result = await async_post(
            "http://127.0.0.1:5000/api/post",
            json={"key": "value"},
            headers={"Content-Type": "application/json"}
        )
        logger.info(f"POST result: {post_result}")
        assert post_result and post_result.get("status") == "success", "POST测试失败"
        assert post_result["data"]["transformed"] == "value_transformed", "数据转换失败"
        assert len(post_result["data"]["sign"]) == 16, "签名格式错误"

        logger.info("所有测试通过！")
        return True
    except AssertionError as e:
        logger.error(f"测试失败: {str(e)}")
        return False

if __name__ == "__main__":
    asyncio.run(test_requests())