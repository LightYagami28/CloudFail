"""
DNSDumpster API for retrieving subdomains
"""

import requests
import re
import base64
from bs4 import BeautifulSoup

class DNSDumpsterAPI:
    """DNSDumpsterAPI Main Handler"""

    def __init__(self, verbose=False, session=None):
        self.verbose = verbose
        self.session = session or requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'})

    def _display_message(self, message):
        if self.verbose:
            print(f'[verbose] {message}')

    def _retrieve_results(self, table):
        results = []
        for row in table.find_all('tr'):
            cells = row.find_all('td')
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            try:
                ip = re.findall(pattern_ip, cells[1].text)[0]
                domain = cells[0].text.split('<br/>')[0].split('>')[1].split('<')[0]
                header = ' '.join(cells[0].text.replace('\n', '').split(' ')[1:])
                reverse_dns = cells[1].find('span', attrs={}).text
                additional_info = cells[2].text
                country = cells[2].find('span', attrs={}).text
                autonomous_system = additional_info.split(' ')[0]
                provider = ' '.join(additional_info.split(' ')[1:])
                provider = provider.replace(country, '')
                data = {
                    'domain': domain,
                    'ip': ip,
                    'reverse_dns': reverse_dns,
                    'as': autonomous_system,
                    'provider': provider,
                    'country': country,
                    'header': header
                }
                results.append(data)
            except Exception:
                pass
        return results

    def _retrieve_txt_record(self, table):
        return [cell.text for cell in table.find_all('td')]

    def search(self, domain):
        dnsdumpster_url = 'https://dnsdumpster.com/'
        self._display_message(f'Retrieving data for {domain}')

        try:
            req = self.session.get(dnsdumpster_url, timeout=10)
            req.raise_for_status()
        except requests.RequestException as e:
            print(f"Error retrieving {dnsdumpster_url}: {e}")
            return []

        soup = BeautifulSoup(req.content, 'html.parser')
        csrf_middleware = soup.find('input', attrs={'name': 'csrfmiddlewaretoken'})['value']
        self._display_message(f'Retrieved token: {csrf_middleware}')

        cookies = {'csrftoken': csrf_middleware}
        data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain, 'user': 'free'}

        try:
            req = self.session.post(dnsdumpster_url, cookies=cookies, data=data, timeout=10)
            req.raise_for_status()
        except requests.RequestException as e:
            print(f"Error posting to {dnsdumpster_url}: {e}")
            return []

        if 'There was an error getting results' in req.content.decode('utf-8'):
            print("There was an error getting results")
            return []

        soup = BeautifulSoup(req.content, 'html.parser')
        tables = soup.find_all('table')

        results = {'domain': domain, 'dns_records': {}}
        results['dns_records']['dns'] = self._retrieve_results(tables[0])
        results['dns_records']['mx'] = self._retrieve_results(tables[1])
        results['dns_records']['txt'] = self._retrieve_txt_record(tables[2])
        results['dns_records']['host'] = self._retrieve_results(tables[3])

        try:
            image_url = f'https://dnsdumpster.com/static/map/{domain}.png'
            image_data = base64.b64encode(self.session.get(image_url, timeout=10).content)
        except Exception:
            image_data = None
        finally:
            results['image_data'] = image_data

        try:
            pattern = rf'/static/xls/{domain}-[0-9{{12}}]\.xlsx'
            xls_url = re.findall(pattern, req.content.decode('utf-8'))[0]
            xls_url = f'https://dnsdumpster.com{xls_url}'
            xls_data = base64.b64encode(self.session.get(xls_url, timeout=10).content)
        except Exception as err:
            print(err)
            xls_data = None
        finally:
            results['xls_data'] = xls_data

        return results
        
