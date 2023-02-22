#!/usr/bin/env python3

# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Command line tool to interact with Chronicle's Config Based Normalizer APIs.

Config Based Normalizer (CBN) APIs allow customers to manage config based
parsers that normalize logs published to Chronicle.

This script provides a command line tool to interact with these APIs and manage
config based parsers. Please see readme file for example usages.
"""

import argparse
import base64
import http
import json
import os
import pathlib
import sys
import time
import urllib

from google.oauth2 import service_account
from googleapiclient import _auth

AUTHORIZATION_SCOPES = ['https://www.googleapis.com/auth/chronicle-backstory']
DEFAULT_CREDS_FILE_PATH = os.path.join(os.environ['HOME'],
                                       '.chronicle_credentials.json')

# URLs for Chronicle CBN API endpoints.
CHRONICLE_API_V1_URL = 'https://backstory.googleapis.com/v1'
CHRONICLE_API_EUROPE_V1_URL = 'https://europe-backstory.googleapis.com/v1'
CHRONICLE_API_UK_V1_URL = 'https://europe-west2-backstory.googleapis.com/v1'
CHRONICLE_API_ASIA_URL = 'https://asia-southeast1-backstory.googleapis.com/v1'

# HTTP Request related constants.
HTTP_REQUEST_TIMEOUT_IN_SECS = 1200
HTTP_REQUEST_HEADERS = {'Content-type': 'application/x-www-form-urlencoded'}


def get_connecting_url(args):
  """Returns endpoint URL based on args."""
  url = CHRONICLE_API_V1_URL
  if args.region == 'EUROPE':
    url = CHRONICLE_API_EUROPE_V1_URL
  elif args.region == 'UK':
    url = CHRONICLE_API_UK_V1_URL
  elif args.region == 'ASIA':
    url = CHRONICLE_API_ASIA_URL

  return url


def get_sample_logs_url(args):
  """Returns sample logs endpoint URL for corresponding region and env."""
  url = f'{get_connecting_url(args)}/tools:retrieveSampleLogs'
  print(f'Connecting to: {url}')
  return url


def get_validate_cbn_url(args):
  """Returns validate cbn endpoint URL for corresponding region and env."""
  url = f'{get_connecting_url(args)}/tools:validateCbnParser'
  print(f'Connecting to: {url}')
  return url


def get_create_parser_url(args):
  """Returns create parser endpoint URL for corresponding region and env."""
  url = f'{get_connecting_url(args)}/tools/cbnParsers'
  print(f'Connecting to: {url}')
  return url


def get_get_parser_url(args, config_id):
  """Returns get parser endpoint URL for corresponding region and env."""
  url = f'{get_connecting_url(args)}/tools/cbnParsers/{config_id}'
  print(f'Connecting to: {url}')
  return url


def get_archive_parser_url(args, config_id):
  """Returns archive parser endpoint URL for corresponding region and env."""
  url = f'{get_connecting_url(args)}/tools/cbnParsers/{config_id}:archive'
  print(f'Connecting to: {url}')
  return url


def get_list_parsers_url(args):
  """Returns list parsers endpoint URL for corresponding region and env."""
  url = f'{get_connecting_url(args)}/tools/cbnParsers'
  print(f'Connecting to: {url}')
  return url


def get_list_parsers_history_url(args, log_type):
  """Returns list parsers history endpoint URL for corresponding region and env."""
  url = (f'{get_connecting_url(args)}/tools/cbnParsers:listCbnParserHistory?' +
         f'log_type={log_type}')
  print(f'Connecting to: {url}')
  return url


def get_list_parser_errors_url(args, log_type, start_date, end_date):
  """Returns list parsers endpoint URL for corresponding region and env."""
  url = (f'{get_connecting_url(args)}/tools/cbnParsers:listCbnParserErrors?' +
         f'log_type={log_type}&start_time={start_date}&end_time={end_date}')
  print(f'Connecting to: {url}')
  return url


def get_http_client(args):
  """Builds and returns authorized http client."""
  # Create a credential using Google Developer Service Account Credential and
  # Backstory API Scope.
  credentials = service_account.Credentials.from_service_account_file(
      args.credentials_file, scopes=AUTHORIZATION_SCOPES)

  # Build a Http client that can make authorized OAuth requests.
  http_client = _auth.authorized_http(credentials)
  return http_client


def make_request(args, url, method='GET', body=None, headers=None):
  """Makes request to the requested endpoint and returns response."""
  http_client = get_http_client(args)
  http_client.http.timeout = HTTP_REQUEST_TIMEOUT_IN_SECS
  response = http_client.request(url, method, body, headers)
  if response[0].status != http.HTTPStatus.OK:
    err = response[1]
    print(json.dumps(json.loads(err), indent=2))
    sys.exit(1)
  return json.loads(response[1])


def generate(args):
  """Generates sample data for writing CBNs using the cli_main CLI utlity.

  Args:
    args: dict containing:
      - log_type: string in the LOG_TYPE format
      - start_date: optional string in the YYYY-MM-DD format  The following
        directory structure will be created (if it doesn't
  exist) and sample data will be generated as follows:  -
    ~/cbn/<log_type>/log_type_1.conf - ~/cbn/<log_type>/log_type_10.conf -
    ~/cbn/<log_type>/log_type_1k.conf - etc.
  """
  sample_sizes = ['1', '10', '1000']
  sample_names = ['1', '10', '1k']

  # Collect data from yesterday if specific date not provided
  start_date = args.start_date
  end_date = args.end_date

  # Verify directory structure exists or create it
  sample_dir = pathlib.Path('{0}/cbn/{1}'.format(pathlib.Path.home(),
                                                 args.log_type.lower()))
  sample_dir.mkdir(parents=True, exist_ok=True)

  # Generate sample data of given sizes
  for i, size in enumerate(sample_sizes):
    outfile = '{0}/{1}_{2}.log'.format(sample_dir, args.log_type.lower(),
                                       sample_names[i])
    print(
        '\nGenerating sample size: {}... '.format(sample_names[i]),
        end='',
        flush=True)
    call_get_sample_logs(args, args.log_type.upper(), start_date, end_date,
                         int(size), outfile)

  print('\nGenerated sample data ({0}); run this to go there:'.format(
      args.log_type.upper()))
  print(f'cd {sample_dir}')


def run(args):
  """Runs the given conf file against the provided log file for analysis."""
  print('\n [cbn_cli]: Running sample... ', flush=True)
  start_time = time.time()

  call_validate_cbn_parser(args, args.conf_file, args.log_file)

  time_elapsed = time.time() - start_time
  print('[cbn_cli]: Runtime {:.5}s'.format(time_elapsed))


def create_parser(args):
  """Submits a given conf file for normalization."""
  print('\n[cbn_cli]: Submitting parser... ', flush=True)

  call_create_parser(args)


def get_parser(args):
  """Gets status of a given parser."""
  print('\n[cbn_cli]: Getting parser... ', flush=True)

  call_get_parser(args, args.config_id)


def list_parsers(args):
  """Gets all parsers for a customer."""
  print('\n[cbn_cli]: List parsers... ', flush=True)

  call_list_parsers(args)


def list_parsers_history(args):
  """Gets all versions of a given parser."""
  print('\n[cbn_cli]: List parsers history... ', flush=True)

  call_list_parsers_history(args, args.log_type)


def archive_parser(args):
  """Archives a Parser given a config id."""
  print('\n[cbn_cli]: Archiving parser... ', flush=True)

  call_archive_parser(args, args.config_id)


def download_parser(args):
  """Downloads Parser to a file, formatted."""
  print('\n[cbn_cli]: Downloading parser... ', flush=True)

  call_download_parser(args, args.config_id, args.log_type)


def parser_errors(args):
  """Gets a list of parser errors."""
  print('\n[cbn_cli]: Getting parser errors... ', flush=True)

  call_parser_errors(args, args.log_type, args.start_date, args.end_date)


def call_create_parser(args):
  """Calls create parser endpoint and handle response."""
  with open(args.conf_file, 'rb') as config_file:
    config_data = config_file.read()

  data = {
      'config': base64.urlsafe_b64encode(config_data),
      'log_type': args.log_type,
      'author': args.author
  }
  body = urllib.parse.urlencode(data)
  create_parser_url = get_create_parser_url(args)

  # Make request and pretty print response
  parser = make_request(args, create_parser_url, 'POST', body,
                        HTTP_REQUEST_HEADERS)
  del parser['config']
  print(json.dumps(parser, indent=2))

  print('To get status of the parser run the following command:')
  print((f'python cbn_cli.py --region={args.region} ' +
         f'--credentials_file={args.credentials_file} ' +
         f'status --config_id={parser["configId"]}'))
  return parser


def call_get_parser(args, config_id):
  """Calls get parser endpoint and pretty prints parser."""
  # Make request and pretty print response
  parser = make_request(args, get_get_parser_url(args, config_id))
  del parser['config']
  print(json.dumps(parser, indent=2))


def call_list_parsers(args):
  """Calls list parser endpoint and handles response."""
  # Make the request
  parsers = make_request(args, get_list_parsers_url(args))
  # Check to see if no CBNs are configured
  if 'cbnParsers' not in parsers:
    print('No CBN parsers currently configured')
    sys.exit(1)
  results = []
  for p in parsers['cbnParsers']:
    del p['config']
    results.append(p)
  print(json.dumps(results, indent=2))


def call_list_parsers_history(args, log_type):
  """Calls list parsers history endpoint and pretty prints parser history."""
  # Make the request
  parser_history = make_request(args,
                                get_list_parsers_history_url(args, log_type))
  if 'cbnParsers' not in parser_history:
    print(json.dumps(parser_history, indent=2))
    sys.exit(1)
  results = []
  for p in parser_history['cbnParsers']:
    del p['config']
    results.append(p)
  print(json.dumps(results, indent=2))


def call_archive_parser(args, config_id):
  """Call archive parser endpoint and pretty prints the parser."""
  # Make the request and pretty print response
  parser = make_request(args, get_archive_parser_url(args, config_id), 'POST')
  del parser['config']
  print(json.dumps(parser, indent=2))


def call_get_sample_logs(args, log_type, start_time, end_time,
                         number_of_entries, file_path):
  """Calls get sample logs endpoint and writes response to file."""
  data = {
      'log_type': log_type,
      'start_time': start_time,
      'end_time': end_time,
      'max_entries': number_of_entries,
  }
  body = urllib.parse.urlencode(data)

  # Make the request
  sample_logs = make_request(args, get_sample_logs_url(args), 'POST', body,
                             HTTP_REQUEST_HEADERS)

  # Parse the response
  sample_logs_data = sample_logs.get('data', [])
  for sample_log in sample_logs_data:
    with open(file_path, 'a') as f:
      f.write(decode_sample_log(sample_log))
      f.write('\n')


def decode_sample_log(sample_log):
  log_bytes = base64.b64decode(sample_log)
  return log_bytes.decode(encoding='utf-8', errors='surrogateescape')


def call_validate_cbn_parser(args, config_file_path, log_file_path):
  """Calls validate CBN parser endpoint and handles response."""
  with open(config_file_path, 'rb') as config_file:
    config_data = config_file.read()

  with open(log_file_path, 'rb') as log_file:
    log_data = log_file.read()

  data = {
      'config': base64.urlsafe_b64encode(config_data),
      'logs': base64.urlsafe_b64encode(log_data)
  }
  body = urllib.parse.urlencode(data)

  # Make the request
  result_response = make_request(args, get_validate_cbn_url(args), 'POST', body,
                                 HTTP_REQUEST_HEADERS)

  output_results = []
  # results for further processing
  results = result_response.get('result')
  if results:
    output_results.append(results)
    for result in results:
      print(result)
  errors = result_response.get('errors')
  if errors:
    for err in errors:
      print(err['errorMsg'])
      print(err['logEntry'])
  return output_results


def call_download_parser(args, config_id, log_type):
  """Calls list parsers endpoint and writes parser config to file."""
  if config_id is not None:
    # Get the parser from config id
    parser = make_request(args, get_get_parser_url(args, args.config_id))
  else:
    # Get the parser of `log_type` from list of parsers
    response = make_request(args, get_list_parsers_url(args))
    if 'cbnParsers' not in response:
      print('No CBN parsers currently configured')
      sys.exit(1)
    found = False
    for p in response['cbnParsers']:
      if p['logType'] == log_type:
        found = True
        parser = p
        break
    if not found:
      print(f'Parser for log type {log_type} not found')
      sys.exit(1)

  decoded_config = base64.b64decode(parser['config'])
  decoded_config = decoded_config.decode('utf-8')
  timestr = time.strftime('%Y%m%d%H%M%S')
  filename = parser['logType'] + '_' + timestr + '.conf'
  print(f'Writing parser to: {filename}')
  with open(filename, 'a') as f:
    f.write(decoded_config)


def call_parser_errors(args, log_type, start_date, end_date):
  """Calls parser errors endpoint and prints the result."""
  if not log_type:
    log_type = 'UNSPECIFIED_LOG_TYPE'
  errors = make_request(
      args, get_list_parser_errors_url(args, log_type, start_date, end_date))
  print(json.dumps(errors, indent=2))


def resolve_file_path(path):
  """Returns the absolute file path resolving home and relative markers."""
  resolved_path = os.path.realpath(os.path.normpath(os.path.expanduser(path)))
  if not os.path.exists(resolved_path):
    raise argparse.ArgumentTypeError('{} does not exist'.format(path))
  return resolved_path


def arg_parser():
  """Builds and returns argument parser for cbn_cli."""
  parser = argparse.ArgumentParser(description='CBN CLI')
  parser.add_argument(
      '--region',
      type=str,
      default='US',
      choices=['US', 'EUROPE', 'UK', 'ASIA'],
      help="""Optionally specify
                        the region for API calls""")
  parser.add_argument(
      '--credentials_file',
      type=resolve_file_path,
      default=DEFAULT_CREDS_FILE_PATH,
      help="""Optionally specify path to Chronicle API credentials file.
      By default, the script assumes file is at `~/.chronicle_credentials.json`.
      """)
  subparsers = parser.add_subparsers()

  # "generate" command
  generate_command = subparsers.add_parser(
      'generate', aliases=['g', 'gen'], help='Generate sample data')
  generate_command.add_argument(
      '-l',
      '--log_type',
      type=str,
      required=True,
      help='The LOG_TYPE for which to sample data')
  generate_command.add_argument(
      '-sd',
      '--start_date',
      type=str,
      help="""Start Date in 'yyyy-mm-dd' format from which to sample data""")
  generate_command.add_argument(
      '-ed',
      '--end_date',
      type=str,
      help="""End Date in 'yyyy-mm-dd' format from which to sample data""")
  generate_command.set_defaults(func=generate)

  # "run" command
  run_command = subparsers.add_parser(
      'run', aliases=['r'], help='Run the parser against the log')
  run_command.add_argument(
      '-c', '--conf_file', type=str, required=True, help="""CBN .conf file""")
  run_command.add_argument(
      '-l',
      '--log_file',
      type=resolve_file_path,
      required=True,
      help="""The .log file to run the parser against""")
  run_command.set_defaults(func=run)

  # "submit" command
  parser_create_command = subparsers.add_parser(
      'submit', help='submits a configuration to the validation queue')
  parser_create_command.add_argument(
      '-l', '--log_type', required=True, help='Log Type')
  parser_create_command.add_argument(
      '-c',
      '--conf_file',
      type=resolve_file_path,
      required=True,
      help='File path to config')
  parser_create_command.add_argument(
      '-a', '--author', required=True, help='Author of the config')
  parser_create_command.set_defaults(func=create_parser)

  # "status" command
  parser_get_command = subparsers.add_parser(
      'status',
      help='status retrieves the state of a parser given the config ID.')
  parser_get_command.add_argument(
      '-i', '--config_id', required=True, help='unique config ID')
  parser_get_command.set_defaults(func=get_parser)

  # "list" command
  parser_list_command = subparsers.add_parser(
      'list', help='list lists all the live parsers for a given customer')
  parser_list_command.set_defaults(func=list_parsers)

  # "history" command
  parser_history_command = subparsers.add_parser(
      'history',
      help='history retrieves all parser submissions given a log type')
  parser_history_command.add_argument(
      '-l', '--log_type', required=True, help='Log Type')
  parser_history_command.set_defaults(func=list_parsers_history)

  # "archive" command
  parser_archive_command = subparsers.add_parser(
      'archive', help='archives a parser given the config ID.')
  parser_archive_command.add_argument(
      '-i', '--config_id', required=True, help='unique config ID')
  parser_archive_command.set_defaults(func=archive_parser)

  # "download" command
  parser_download_command = subparsers.add_parser(
      'download', help='download parser code given log type')
  dgroup = parser_download_command.add_mutually_exclusive_group(required=True)
  dgroup.add_argument('-l', '--log_type', help='Log Type')
  dgroup.add_argument('-i', '--config_id', help='unique config ID')
  parser_download_command.set_defaults(func=download_parser)

  # "error" command
  error_command = subparsers.add_parser(
      'error', aliases=['e', 'err'], help='Get CBN errors')
  error_command.add_argument(
      '-l',
      '--log_type',
      type=str,
      help='The LOG_TYPE for which errors are to be retrieved')
  error_command.add_argument(
      '-sd',
      '--start_date',
      type=str,
      required=True,
      help=("Start Date in 'yyyy-mm-dd' format from which errors are to be " +
            'retrieved'))
  error_command.add_argument(
      '-ed',
      '--end_date',
      type=str,
      required=True,
      help=("End Date in 'yyyy-mm-dd' format to which errors are to be " +
            'retrieved'))
  error_command.set_defaults(func=parser_errors)
  return parser


def main(input_args):
  parser = arg_parser()
  parsed_args = parser.parse_args(input_args)
  parsed_args.func(parsed_args)


if __name__ == '__main__':
  main(sys.argv[1:])
