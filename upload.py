import urllib2
import json
import base64
import hashlib
import os
import os.path
import sys

b2_opts = {
    'b2_hex_account_id': sys.argv[1],
    'b2_app_key': sys.argv[2],
    'local_base_directory': sys.argv[3],
    'b2_bucket_id': sys.argv[4],
    'b2_api_base_url': 'https://api.backblazeb2.com/b2api/v1/',
    'b2_auth_token': None,
    'b2_upload_auth_token': None,
    'b2_api_url': None,
    'b2_download_url': None,
    'b2_upload_url': None,
    'b2_min_part_size': None
}


def getAccountAuth(hex_acc_id, app_key):
    basic_auth_string = 'Basic ' + base64.b64encode(hex_acc_id + ':' + app_key)
    headers = {'Authorization': basic_auth_string}

    request = urllib2.Request(
        b2_opts['b2_api_base_url'] + 'b2_authorize_account',
        headers=headers
    )

    response = urllib2.urlopen(request)
    response_data = json.loads(response.read())
    response.close()
    return response_data


def get_b2_upload_url(bucket_id):
    if not b2_opts['b2_api_url'] or not b2_opts['b2_auth_token']:
        b2_opts['b2_auth_token'], b2_opts['b2_api_url'], b2_opts['b2_download_url'], b2_opts['b2_min_part_size'] = getAccountAuth(
            b2_opts['b2_hex_account_id'], b2_opts['b2_app_key'])

    req = urllib2.Request('%s/b2api/v1/b2_get_upload_url' % b2_opts['b2_api_url'],
                          json.dumps({'bucketId': bucket_id}),
                          headers={'Authorization': b2_opts['b2_auth_token']})

    resp = urllib2.urlopen(req)
    data = json.loads(resp.read())
    resp.close()
    return data


def do_upload_file(file_abs_location, b2_bucket_id):
    if not b2_opts['b2_auth_token']:
        account_auth_data = getAccountAuth(b2_opts['b2_hex_account_id'], b2_opts['b2_app_key'])
        b2_opts['b2_auth_token'] = account_auth_data['authorizationToken']
        b2_opts['b2_api_url'] = account_auth_data['apiUrl']
        b2_opts['b2_download_url'] = account_auth_data['downloadUrl']
        b2_opts['b2_min_part_size'] = account_auth_data['recommendedPartSize']

    headers = {
        'Authorization': b2_opts['b2_auth_token'],
        'X-Bz-File-Name': urllib2.quote(os.path.relpath(file_abs_location, b2_opts['local_base_directory']).encode('utf-8')),
        'Content-Type': 'b2/x-auto',
    }

    with open(file_abs_location, 'rb') as f:
        print "Uploading", file_abs_location
        file_data = f.read()
        sha1_of_file_data = hashlib.sha1(file_data).hexdigest()
        headers['X-Bz-Content-Sha1'] = sha1_of_file_data

        if not b2_opts['b2_upload_url'] or not b2_opts['b2_upload_auth_token']:
            b2_upload_url_data = get_b2_upload_url(b2_bucket_id)
            b2_opts['b2_upload_auth_token'] = b2_upload_url_data['authorizationToken']
            b2_opts['b2_upload_url'] = b2_upload_url_data['uploadUrl']

        request = urllib2.Request(b2_opts['b2_upload_url'], file_data, headers)

    try:
        resp = urllib2.urlopen(request)
        resp_data = json.loads(resp.read())
    except urllib2.HTTPError, e:
        print e.reason
        print resp_data
    except Exception, e:
        print e,
        print resp_data


def generate_file_list(base_directory):
    directories_to_traverse = [base_directory]
    file_list = []
    while directories_to_traverse:
        current_dir = directories_to_traverse.pop()
        dir_contents = os.listdir(current_dir)
        while dir_contents:
            entry = os.path.join(current_dir, dir_contents.pop())
            if os.path.isdir(entry):
                directories_to_traverse.append(entry)
            elif os.path.isfile(entry):
                file_list.append(entry)
                print "Found file:", entry

    return file_list


file_list = generate_file_list(b2_opts['local_base_directory'])
while file_list:
    do_upload_file(file_list.pop(), b2_opts['b2_bucket_id'])
