CASEINSENSITIVE = True
CASESENSITIVE = False

'''
YOUR CUSTOM FUNCTIONS HERE
'''

REQUEST_PATTERNS = [
    (r"request_regex_1", "all", CASEINSENSITIVE),
    (r"request_regex_2", "all", CASEINSENSITIVE),
]
RESPONSE_PATTERNS = [
    (r"response_regex_1", "all", CASEINSENSITIVE),
    (r"response_regex_2", "all", CASEINSENSITIVE),
]
REQUEST_FUNCTIONS = [
    request_func_1,
    request_func_2,
]
RESPONSE_FUNCTIONS = [
    response_func_1,
    response_func_2,
]
