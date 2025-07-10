from mitmproxy import http
import re

class SimpleIDSIPS:
    """Minimal IDS/IPS plugin skeleton"""
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
        # TODO: 
        return
    

    def addRequestFunction(self, func):
        # TODO: 
        return


    def request(self, flow: http.HTTPFlow) -> None:
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
                        flow.kill()
                        return
                elif location == 'headers':
                    if self._matchRegex(headers, regex):
                        flow.kill()
                        return
                elif location == 'body':
                    if self._matchRegex(body, regex):
                        flow.kill()
                        return
                else:
                    raise ValueError(f"Invalid response location: {location}")

        # TODO: aggiungere controllo delle specifiche funzioni

    def response(self, flow: http.HTTPFlow) -> None:
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
                        flow.kill()
                        return
                elif location == 'headers':
                    if self._matchRegex(headers, regex):
                        flow.kill()
                        return
                elif location == 'body':
                    if self._matchRegex(body, regex):
                        flow.kill()
                        return
                else:
                    raise ValueError(f"Invalid response location: {location}")
        # TODO: aggiungere controllo delle specifiche funzioni

    def addRegexFromRequest(self, flow: http.HTTPFlow):
        # TODO:
        return

    def addRegexFromResponse(self, flow: http.HTTPFlow):
        # TODO: 
        return
ids = SimpleIDSIPS()

'''
to add custom rules:
def customRule(flow):
    ua = flow.request.headers.get('User-Agent', '')
    try:
        body = flow.request.get_text()
    except ValueError():
        body = ''
    return ua == 'checker' and body == 'attacco sgravato'

ids.addRequestFunction(customRule)
'''

addons = [ids]
