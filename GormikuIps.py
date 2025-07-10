from mitmproxy import http
import re
import asyncio
import time

CASEINSENSITIVE = True
CASESENSITIVE = False

class SimpleIDSIPS:
    """Minimal IDS/IPS plugin skeleton"""
    async def _droppacket(self, flow: http.HTTPFlow):
        await asyncio.sleep(10)
        flow.response = http.Response.make(
                204,                         # 204 No Content
                b"",                         # no body
                {
                    "Content-Type": "text/plain",
                    "Connection": "keep-alive"
                }
            )
        return


    def __init__(self):
        self.request_patterns = {'url': [], 'headers': [], 'body': []}
        self.response_patterns = {'url': [], 'headers': [], 'body': []}
        self.request_rules = []
        self.response_rules = []


    def _matchRegex(self, content, regex):
        if regex.search(content):
            return regex.pattern
        return None


    def addRequestPattern(self, pattern: str, location: str = 'body', ignore_case: bool = False):
        flags = re.IGNORECASE if ignore_case else 0
        regex = re.compile(pattern, flags)
        if location == 'all':
            targets = self.request_patterns.keys()
        else:
            targets = [location]

        for loc in targets:
            if loc not in self.request_patterns:
                raise ValueError(f"Invalid request location: {loc}")
            self.request_patterns[loc].append(regex)
        

    def addResponsePattern(self, pattern: str, location: str = 'body', ignore_case: bool = False):
        flags = re.IGNORECASE if ignore_case else 0
        regex = re.compile(pattern, flags)
        if location == 'all':
            targets = self.response_patterns.keys()
        else:
            targets = [location]

        for loc in targets:
            if loc not in self.response_patterns:
                raise ValueError(f"Invalid response location: {loc}")
            self.response_patterns[loc].append(regex)


    def addRequestFunction(self, func):
        self.request_rules.append(func)
    

    def addResponseFunction(self, func):
        self.response_rules.append(func)

    async def request(self, flow: http.HTTPFlow) -> None:
        # TODO: inspect flow.request and drop if necessary
        url = flow.request.pretty_url
        headers = '\r\n'.join(f"{k}: {v}" for k, v in flow.request.headers.items())
        try:
            body = flow.request.get_text()
        except ValueError:
            body = ''

        # Check each 
        for location in self.request_patterns.keys():
            for regex in self.request_patterns[location]:
                if location == 'url':
                    if self._matchRegex(url, regex):
                        await self._droppacket(flow)
                        return
                elif location == 'headers':
                    if self._matchRegex(headers, regex):
                        await self._droppacket(flow)
                        return
                elif location == 'body':
                    if self._matchRegex(body, regex):
                        await self._droppacket(flow)
                        return
                else:
                    raise ValueError(f"Invalid response location: {location}")

        # Checking custom functions
        for rule in self.request_rules:
            try:
                if rule(flow):
                    await self._droppacket(flow)
                    return
            except Exception:
                pass

    async def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return
        url = flow.request.pretty_url
        headers = '\r\n'.join(f"{k}: {v}" for k, v in flow.response.headers.items())
        try:
            body = flow.response.get_text()
        except ValueError:
            body = ''

        # Check each 
        for location in self.response_patterns.keys():
            for regex in self.response_patterns[location]:
                if location == 'url':
                    if self._matchRegex(url, regex):
                        await self._droppacket(flow)
                        return
                elif location == 'headers':
                    if self._matchRegex(headers, regex):
                        await self._droppacket(flow)
                        return
                elif location == 'body':
                    if self._matchRegex(body, regex):
                        await self._droppacket(flow)
                        return
                else:
                    raise ValueError(f"Invalid response location: {location}")
        for rule in self.request_rules:
            try:
                if rule(flow):
                    await self._droppacket(flow)
                    return
            except Exception:
                pass
