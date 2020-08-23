#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
中间人攻击

@author mybsdc <mybsdc@gmail.com>
@date 2020/8/22
@time 10:06
"""

import re
import json
from mitmproxy import ctx, http


class MITM:
    def __init__(self):
        pass

    def request(self, flow: http.HTTPFlow) -> None:
        pass

    def response(self, flow: http.HTTPFlow) -> None:
        if 'findListByClassifyId' in flow.request.pretty_url:
            ctx.log.info('栗子摄影 APP 正在搞事情，即将篡改响应')
            raw_response = flow.response.get_text()
            ctx.log.alert(raw_response)

            content = re.sub(r'isPreview":(\d+),"', 'isPreview":2,"', raw_response, flags=re.I)
            ctx.log.info('响应修改后')
            ctx.log.alert(content)

            flow.response.set_text(content)


addons = [ # 不能有 if __name__ == '__main__': 关键字，此处的逻辑应该是 mitmproxy 内部做了处理的
    MITM()
]
