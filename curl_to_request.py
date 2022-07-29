# -*- coding: UTF-8 -*-
class curl_to_request:
    __url = ''
    __method = ''
    __request = {}
    __headers = {}
    __payload = {}
    __files=[]
    def __init__(self, curl_commond):
        self.__convert_curl(curl_commond)
        pass
    def __convert_curl(self, curl_commond):
        import argparse
        import shlex

        argv = shlex.split(str(curl_commond).strip())
        del argv[0]

        # Now parse it into meaningful data
        parser = argparse.ArgumentParser()
        parser.add_argument('url')
        parser.add_argument('--request', '-X', dest='method', default='GET')
        parser.add_argument('--header', '-H', dest='headers', action='append')
        parser.add_argument('--data-urlencode', action='append', dest='payload_urlencode')
        parser.add_argument('--data-raw', dest='payload_raw')
        parser.add_argument('--data','-d', dest='payload_data')
        parser.add_argument('--data-binary', dest='payload_bin')
        parser.add_argument('--form', dest='payload_form', action='append')
        # parser.add_argument('--compressed', default='')
        args, unknown = parser.parse_known_args(argv)
        # print(args)
        # print(unknown)

        # Start to build the call into requests
        if args.url:
            self.__url = args.url

        # print(args.method)
        self.__method = args.method

        if args.headers:
            self.__headers = {}
            for header in args.headers:
                name, _, value = header.partition(': ')
                self.__headers[name] = value
        # print(self.headers)

        if args.payload_urlencode:
            self.__payload = '&'.join(args.payload_urlencode)

        if args.payload_form:
            for form_data in args.payload_form:
                form_datas = str(form_data).split('=')
                if len(form_datas) == 2:
                    self.__payload[form_datas[0]] = form_datas[1].replace('"', '')

        if args.payload_raw:
            self.__payload = str(args.payload_raw)

        if args.payload_data:
            self.__payload = str(args.payload_data)

        if args.payload_bin:
            self.__payload = str(args.payload_bin)
        # print(self.payload)
        pass

    def call_request(self, _verify=False, _log=False):
        if _log:
            print("url:", self.__url)
            print("method:", self.__method)
            print("headers:", self.__headers)
            print("payload:", self.__payload)

        import requests
        requests.packages.urllib3.disable_warnings()
        response = requests.request(self.__method, self.__url, headers=self.__headers,
                                    data=self.__payload, files=self.__files, verify = _verify)
        return response
        pass

if (__name__ == '__main__'):
    # Lex the curl command into its constituent arguments
    example = '''
curl 'https://cms-bucket.ws.126.net/2021/1220/4e3db11cj00r4e9my001hc0003m007tc.jpg' \
  -H 'authority: cms-bucket.ws.126.net' \
  -H 'accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9' \
  -H 'accept-language: zh-CN,zh;q=0.9' \
  -H 'cache-control: max-age=0' \
  -H 'sec-ch-ua: ".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"' \
  -H 'sec-ch-ua-mobile: ?0' \
  -H 'sec-ch-ua-platform: "macOS"' \
  -H 'sec-fetch-dest: document' \
  -H 'sec-fetch-mode: navigate' \
  -H 'sec-fetch-site: none' \
  -H 'sec-fetch-user: ?1' \
  -H 'upgrade-insecure-requests: 1' \
  -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36' \
  --compressed
    '''.strip()

    utor = curl_to_request(example)
    resp = utor.call_request(False, True)
    print(resp.content)
    # print(utor.call_request(False, True))