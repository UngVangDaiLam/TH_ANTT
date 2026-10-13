def filter_targets(ip_list, whitelist=None, blacklist=None):
    whitelist = set(whitelist or [])
    blacklist = set(blacklist or [])
    result = []
    for ip in ip_list:
        if blacklist and ip in blacklist:
            continue
        if whitelist and ip not in whitelist:
            continue
        result.append(ip)
    return result
