#!/usr/bin/python
from __future__ import print_function
import urllib
import requests
import hashlib
import time
import base64
import sys
import argparse


# NetProfiler and Steelhead https ssl certificates are self signed by default.
# IF the user has not replaced these certificates with certificates signed by
# an ssl certificate authority recognized by clients in the environment then
# these examples will fail. I have taken the liberty of disabling ssl cert
# checking. Please carefully consider the implications of this in production
# code
# ***** WARNING: eliminates ssl certificate checking. *****
#requests.packages.urllib3.disable_warnings()

# fqdn or ip address of our test host
test_host = "127.0.0.1"
# name of the file with our OAuth2 key in it.
test_code = "test_oauth.key"

# Define the start of a URL
host_part = 'https://{host_id}'

# The OAuth Token URL
token_url = '/api/common/1.0/oauth/token'


# going to do this a bunch
def encode(s):
    return base64.urlsafe_b64encode(s)


# We will need a wrapper of the request methods because of the number of times
# we will be doing this.
def do_request(host, url, data=None, headers=None):
    url_start = host_part.format(host_id = host)
    request_url = "{0}{1}".format(url_start, url)
    r = None
    if data is None:
        # no data is a get request.
        # verify is set to false so SSL errors don't cause problems
        # allow_redirects is false because the NetProfiler REST API
        # uses the location header in a redirect to pass back OAuth2
        # key data.
        r = requests.get(request_url,
                         headers=headers,
                         verify=False,
                         allow_redirects=False)
    else:
        r = requests.post(request_url,
                          data=data,
                          headers=headers,
                          verify=False,
                          allow_redirects=False)
    return r


def main():

    # ENTER HERE
    # First thing I am doing is a bit of simple argparse. This just
    # allows the sample script to take in arguments with very little code.
    parser = argparse.ArgumentParser(description ='Test Script - REST API')
    parser.add_argument('-n', '--netpro-host',
                        help ='NetProfiler host name or IP.',
                        type =str,
                        default='',
                        metavar = 'netprofiler_host')
    parser.add_argument('-s', '--steelhead-host',
                        help ='Steelhead DNS Name or IP Address.',
                        type =str,
                        required =True,
                        metavar='steelhead_host')
    parser.add_argument('-a', '--auth-code',
                        help =('Path to file containing auth code.'),
                        type =str,
                        required =True,
                        metavar='auth_code')
    parser.add_argument('-u', '--user',
                        help ='User name.',
                        type =str,
                        default ="admin")
    parser.add_argument('-p', '--passwd',
                        help ='Password.',
                        type =str,
                        default="admin")
    parser.add_argument('-d', '--debug',
                        help ='Disable Printing debug.',
                        action ='store_false')
    args = parser.parse_args()
    print(args)

    # fetch the OAuth2 key from our test file
    with open(args.auth_code, 'r') as f:
        file_text = f.readline()
        # strip the text just in case some white space got in there.
        oauth_code = file_text.strip()

    # The first step in OAuth2 is to package up the data of a token
    # request. We will use the token in subsequent authenticated requests
    header_encoded = encode("{\"alg\":\"none\"}\n")
    # We don't sign our REST calls so empty string
    signature_encoded = ''
    assertion = '.'.join([header_encoded, oauth_code, signature_encoded])
    grant_type = 'access_code'
    print(args.steelhead_host)

    # NetProfiler views the state variable as optional. Against a NetProfiler
    # this can be an empty sting. Steelhead requires this. Best to use it in
    # all cases. This is the only difference between Steelhead and NetProfiler
    # implementations.
    state = hashlib.md5(str(time.time())).hexdigest()
    data = {'grant_type': grant_type,
            'assertion': assertion,
            'state': state}

    # Now that our data is prepped lets make the request
    # I am going to use json.loads to parse the data returned
    # so I add an Accept header indicating I want JSON back.
    if args.netpro_host:
        oauth_netpro = do_request(args.netpro_host,
                                  token_url,
                                  data=data,
                                  headers={'Accept': 'application/json'})
        # turn the result into python objects
        oauth_netpro_obj = oauth_netpro.json()

        # check if something went wrong with the request
        # This is just here as an example of ways you could catch failures in
        # OAuth2 token requests. I am not going to repeat it is subsequent examples
        if oauth_netpro_obj['state'] != state:
            print("Inconsistent state value in OAuth response")
            sys.exit(1)
        # NetProfiler has a url in its REST API that will return a list of
        # the systems users. As an example of retrieving an authenticated URL
        # we will use the token we just got to retrieve that list.
        # This is a good test URL because it requires authentication
        users_url = '/api/profiler/1.5/users'

        # this request will have both an authentication and a 'Accept' header.
        # The auth header is simply "Bearer <token_text>" in a string.
        auth_hdr_data = 'Bearer {0}'.format(oauth_netpro_obj['access_token'])
        auth_hdr = {'Authorization': auth_hdr_data,
                    'Accept': 'application/json'}

        users_req = do_request(args.netpro_host,
                               users_url,
                               headers=auth_hdr)

        users_obj = users_req.json()
        if args.debug:
            print("DEBUG: Our token is: {token}\n".format(token =
                                                   oauth_netpro_obj['access_token']))
        # So now we have our token. Lets use it to make an authenticated request


        if args.debug:
            print("DEBUG: There are {0} user(s) on {1}".format(len(users_obj),
                                                               args.netpro_host))
            for user in users_obj:
                print ("User {username} - Auth Type: {authentication_type}, Role: "
                       "{role}".format(username=user['username'],
                                   authentication_type=user['authentication_type'],
                                   role=user['role']))
            print("\n")


    # We can do the same thing against our Steelhead host as well.
    # if the steelhead_host has been defined lets try
    if args.steelhead_host:
        # I am doing this to demonstrate how much of the above process is
        # identical on the Steelhead
        # The only real change is the authenticated URL we are going to fetch
        # The 2.0 api should be on any current Steelhead
        sh_apps_url = '/api/sh.appflow/2.0/l7protocols'

        # only the hostname has changed. Otherwise we can use the exact same
        # request.
        oauth_sh = do_request(args.steelhead_host,
                              token_url,
                              data=data,
                              headers={'Accept': 'application/json'})
        oauth_sh_obj = oauth_sh.json()
        # The token we get from the Steelhead is different so we have to
        # redefine the auth header with it. The format is identical.
        auth_hdr = {'Authorization': 'Bearer {0}'.format(
                                                oauth_sh_obj['access_token']),
                    'Accept': 'application/json'}
        applist_sh = do_request(args.steelhead_host,
                                sh_apps_url,
                                headers=auth_hdr)

        applist_obj = applist_sh.json()

        if args.debug:
            print ("DEBUG: There are {0} Apps defined on"
                   " {1}".format(len(applist_obj), args.steelhead_host))

    # NetProfiler has the ability to allow users to request that an OAuth2
    # key be created and then to allow the user to utilize that key. This
    # combines username and password basic authentication with OAuth2.

    # This url is unique in this test script because it uses URL parameters.
    # These are required because the URL only supports GET operations.
    # Create a url with params to cause a unique key to be created.
    # I am using the state variable to uniquely identify this access code
    # you can use anything for this purpose or give all the codes the same desc.
    # NetProfiler does not require uniqueness.
    auth_url_str = ('/api/common/1.0/oauth/authorize?response_type=code&desc='
                    'TestOAuth2Code_{0}'.format(state))
    netpro_apps_url = '/api/profiler/1.5/applications'

    # URL encode the username and password for the headers
    u_n_p = encode("{user}:{passwd}".format(user=args.user,
                                            passwd=args.passwd))

    # Don't care what format the response comes back in so no JSON header
    # We are only interested in the headers returned.
    # Note: Any NetProfiler example using OAuth2 token headers could also be
    # done using this header with just username:password auth. The only
    # difference is the header.
    user_auth_hdr = {'Authorization': 'Basic {0}'.format(u_n_p)}

    newkey_resp = do_request(args.netpro_host,
                             auth_url_str,
                             headers=user_auth_hdr)
    # note that in this case we don't pay any attention to the html/json
    # returned. We just want the header object. See above.
    header_dict = newkey_resp.headers
    local_header = header_dict.get('Location')


    new_auth_code = ''
    # if we got a new access code then the location header will start with
    # '?code=' followed by the access code string.
    if (local_header is not None and
        local_header[:6] == '?code='):
        new_auth_code = local_header[6:].strip()
        new_auth_code = urllib.unquote(new_auth_code)

    # if new_auth_code != '':
    #     # We got a code. Now we can use it. Lets see how many apps this
    #     # NetProfiler has. Only comments on the deltas. We are going to use our
    #     # new OAuth2 key to get a token and then get the protected apps
    #     # url in the NetProfiler REST API. Same things we have done above
    #
    #     # Get the token. First redo the assertion because we have a new code
    #     assertion = '.'.join([header_encoded, new_auth_code, signature_encoded])
    #     # Rebuild the data now that we have a new assertion
    #     data = {'grant_type': grant_type,
    #             'assertion': assertion,
    #             'state': state}
    #
    #     # netpro_newtoken_req = do_request(args.netpro_host,
    #     #                                  token_url,
    #     #                                  data=data,
    #     #                                  headers={'Accept': 'application/json'})
    #
    #     # new_key_obj = netpro_newtoken_req.json()
    #
    #     # new token so new request headers
    #     auth_hdr = {'Authorization': 'Bearer {0}'.format(
    #                                                new_key_obj['access_token']),
    #                 'Accept': 'application/json'}
    #     netpro_applist = do_request(args.netpro_host,
    #                                      netpro_apps_url,
    #                                      headers=auth_hdr)
    #
    #     netpro_applist_obj = netpro_applist.json()
    #
    #     if args.debug:
    #         print ("DEBUG: There are {0} Apps defined on"
    #                " {1}".format(len(netpro_applist_obj), args.netpro_host))


if __name__ == "__main__":
   main()