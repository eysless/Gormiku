from GormikuIps import SimpleIDSIPS

ids = SimpleIDSIPS()

################################## TO ADD CUSTOM FUNCTION ################################################
'''
def customRule(flow):
    ua = flow.request.headers.get('User-Agent', '')
    try:
        body = flow.request.get_text()
    except ValueError():
        body = ''
    return ua == 'checker' and body == 'attacco sgravato'

ids.addRequestFunction(customRule)

IMPORTANT: THE FUNCTION MUST ONLY PASS THE FLOW ARGUMENT
'''
################################## TO ADD CUSTOM REGEX ################################################
'''
regex = '/customRegex/'
ids.addRequestPattern(regex, 'body', CASESENSITIVE)

THE LOCATION OPTIONS ARE: 'url', 'body', 'headers', 'all'
'''
addons = [ids]
