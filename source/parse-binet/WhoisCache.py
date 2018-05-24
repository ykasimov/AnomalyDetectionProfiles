# whois_cache = {}
import json
import time
import sys
#import ipwhois
#from ipwhois.utils import get_countries
#import jsonpickle


class RadpCache ():
    def __init__(self):
        # self.dst_ip ='89.185.236.188'
        self.whois_cache = {}
        self.whois_country_cache = {}

    def get_whois_data(self, dst_ip):
        desc = {}
        try:
            import ipwhois
            from ipwhois.utils import get_countries
        except ImportError:
            print ('The ipwhois library is not install. pip install ipwhois')
            return False
        # is the ip in the cache
        try:
            desc = self.whois_cache[dst_ip]
        except KeyError:
            # Is not, so just ask for it
            # time.sleep (1)
            try:
                obj = ipwhois.IPWhois (dst_ip)
                # data = obj.lookup_whois()
                data = obj.lookup_rdap (depth=1)
                try:
                    jas = json.loads (json.dumps (data))
                    desc = jas

                    # self.desc = jas
                    # self.desc = data['nets'][0]['description'].strip().replace('\n',' ') + ',' \
                    #            + data['nets'][0]['country']
                except AttributeError:
                    # There is no description field
                    desc = ""
            except ipwhois.IPDefinedError as e:
                # if 'Multicast' in e:
                #    self.desc['country'] = 'Multicast'
                # elif 'RFC 1918.' in e:
                # self.desc['country'] = 'Private Use'
                print('local network ip')
            except ipwhois.WhoisLookupError:
                print ('Error looking the whois of {}'.format (dst_ip))
                # continue with the work
            except ValueError:
                # Not a real IP, maybe a MAC
                pass
            except IndexError:
                # Some problem with the whois info. Continue
                pass
            except TypeError:
                # Some problem with the whois info. Continue
                pass
            except ipwhois.HTTPLookupError:
                # Some problem with the whois info. Continue
                with open ('whoiscahce.json', 'w') as fp:
                    json.dump (self.whois_cache, fp)
                with open ('country_cache.json', 'w') as fp:
                    json.dump (self.whois_country_cache, fp, indent=2)
            except ipwhois.HTTPRateLimitError:
                print ('HTTPRateLimitError')
                with open ('whoiscahce.json', 'w') as fp:
                    json.dump (self.whois_cache, fp, indent=2)
                with open ('country_cache.json', 'w') as fp:
                    json.dump (self.whois_country_cache, fp, indent=2)
                sys.exit (1)
            # Store in the cache
            self.whois_cache[dst_ip] = desc
        return desc

    def get_country_for_ip(self, dst_ip):
        try:
            import ipwhois
            from ipwhois.utils import get_countries
        except ImportError:
            print ('The ipwhois library is not install. pip install ipwhois')
            return False
        countries = get_countries ()
        desc = self.get_whois_data (dst_ip)

        try:
            country = countries[desc['asn_country_code']]
            self.whois_cache[dst_ip]['country_name'] = country
            self.whois_country_cache[dst_ip] = country
        except KeyError:
            try:
                country = desc['asn_country_code']
            except KeyError:
                country = 'Unknown'
        return country

    def get_organization_of_ip(self, ip):
        desc = self.get_whois_data (ip)
        try:
            organisation = self.whois_cache[ip]['network']['name']
        except KeyError:
            organisation = ''
        return organisation

    def get_country_cache(self):
        return self.whois_country_cache

    def get_whois_cache(self):
        return self.whois_cache
        # aaaa = RadpCache()
        # print(aaaa.get_whois_data('50.7.254.4'))
        # print (whois_cache)
        # print(whois_cache['89.185.236.188'])
