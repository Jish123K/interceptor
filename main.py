import asyncio

import logging

import re

from mitmproxy import http, ctx

from mitmproxy.exceptions import HttpException

logging.basicConfig(level=logging.INFO)

class Interceptor:

    def __init__(self):

        self.blocklist = set()

        self.response_modifications = {}

    def request(self, flow: http.HTTPFlow) -> None:

        ctx.log.info(f"Intercepted request: {flow.request.pretty_url}")

        if flow.request.pretty_url in self.blocklist:

            ctx.log.warn(f"Blocked request to {flow.request.pretty_url}")

            flow.kill()

        else:

            flow.intercept()

    def response(self, flow: http.HTTPFlow) -> None:

        ctx.log.info(f"Intercepted response: {flow.request.pretty_url}")

        content_type = flow.response.headers.get("Content-Type", "")

        if content_type.startswith("text/html"):

            # modify HTML response

            if "text/html" in self.response_modifications:

                flow.response.content = self._modify_html(flow.response.content, self.response_modifications["text/html"])

        elif content_type.startswith("application/json"):

            # modify JSON response

            if "application/json" in self.response_modifications:

                flow.response.content = self._modify_json(flow.response.content, self.response_modifications["application/json"])

    def _modify_html(self, content: bytes, modifications: dict) -> bytes:

        html = content.decode(errors="ignore")

        for pattern, replacement in modifications.items():

            html = re.sub(pattern, replacement, html)

        return html.encode()

    def _modify_json(self, content: bytes, modifications: dict) -> bytes:

        json_data = json.loads(content)

        for key, value in modifications.items():

            json_data[key] = value

        return json.dumps(json_data).encode()

    def add_blocklist(self, urls: list) -> None:

        self.blocklist.update(urls)

    def add_response_modifications(self, content_type: str, modifications: dict) -> None:

        self.response_modifications[content_type] = modifications

def start_interceptor():

    interceptor = Interceptor()

    mitmproxy_options = {

        "port": 8080,

        "ssl_insecure": True,

        "mode": "reverse:http://localhost:80",

        "listen_host": "0.0.0.0",

        "listen_port": 8081

    }

    with open("blocklist.txt", "r") as f:

        interceptor.add_blocklist(f.read().splitlines())

    with open("response_modifications.json", "r") as f:

        modifications = json.load(f)

        for content_type, values in modifications.items():

            interceptor.add_response_modifications(content_type, values)

    runner = asyncio.new_event_loop().run_until_complete(http.run(

        **mitmproxy_options,

        http_proxy=False,

        intercept=interceptor.request,

        response=interceptor.response

    ))

if __name__ == "__main__":

    start_interceptor()

