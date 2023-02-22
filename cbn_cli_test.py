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
"""Tests for chronicle cbn_cli."""

import base64
import json
import unittest
from unittest import mock

from parameterized import parameterized
from . import cbn_cli


class CbnCliTest(unittest.TestCase):

  def __init__(self, *args, **kwargs):
    super(CbnCliTest, self).__init__(*args, **kwargs)
    self.parser_file_name = 'test.conf'
    self.log_type = 'test_log_type'
    self.author = 'test_user'
    self.config_id = 'test_config_id'
    self.parser = json.loads('{{'
                             '"configId": "{}",'
                             '"author": "{}",'
                             '"logType": "{}"'
                             '}}'.format(self.config_id, self.author,
                                         self.log_type))
    self.parser['config'] = base64.b64encode(b'test')
    self.parsers = json.loads('{"cbnParsers": "[]"}')
    self.parsers['cbnParsers'] = [self.parser]

  def setUp(self):
    super(CbnCliTest, self).setUp()
    self.mock_make_request = mock.patch('cbn_cli.make_request').start()

    self.mock_patch = mock.patch('os.path.exists').start()
    self.mock_open = mock.patch('builtins.open',
                                mock.mock_open(read_data=b'abcd')).start()

  def tearDown(self):
    super(CbnCliTest, self).tearDown()
    self.mock_make_request.stop()
    self.mock_patch.stop()

  @parameterized.expand([
      ('', cbn_cli.CHRONICLE_API_V1_URL),
      ('EUROPE', cbn_cli.CHRONICLE_API_EUROPE_V1_URL),
      ('UK', cbn_cli.CHRONICLE_API_UK_V1_URL),
      ('ASIA', cbn_cli.CHRONICLE_API_ASIA_URL),
  ])
  def test_get_connecting_url(self, region, expected_url):
    args = cbn_cli.arg_parser().parse_args()
    args.region = region
    self.assertEqual(expected_url, cbn_cli.get_connecting_url(args))

  @mock.patch('os.path.exists', lambda x: True)
  def test_validate_cbn_parser(self):
    log_file = 'test.log'
    cmd_line_args = 'run -l={} -c={}'.\
        format(log_file, self.parser_file_name)
    url = '{}/tools:validateCbnParser'.format(cbn_cli.CHRONICLE_API_V1_URL)

    # Test response with result.
    self.mock_make_request.return_value = json.loads('{"result": "[]"}')
    args = cbn_cli.arg_parser().parse_args(cmd_line_args.split())
    cbn_cli.run(args)
    self.mock_open.assert_called_with(cbn_cli.resolve_file_path(log_file), 'rb')
    self.mock_make_request.assert_called_with(args, url, 'POST', mock.ANY,
                                              cbn_cli.HTTP_REQUEST_HEADERS)

    # Test error response.
    self.mock_make_request.return_value = json.loads('{"errors": []}')
    args = cbn_cli.arg_parser().parse_args(cmd_line_args.split())
    cbn_cli.run(args)
    self.mock_open.assert_called_with(cbn_cli.resolve_file_path(log_file), 'rb')
    self.mock_make_request.assert_called_with(args, url, 'POST', mock.ANY,
                                              cbn_cli.HTTP_REQUEST_HEADERS)

  @mock.patch('os.path.exists', lambda x: True)
  def test_create_parser(self):
    cmd_line_args = 'submit -l={} -c={} -a={}'.\
        format(self.log_type, self.parser_file_name, self.author)
    url = '{}/tools/cbnParsers'.format(cbn_cli.CHRONICLE_API_V1_URL)
    parser = json.loads('{"configId": "test_config_id", "config": "test"}')
    self.mock_make_request.return_value = parser

    args = cbn_cli.arg_parser().parse_args(cmd_line_args.split())
    cbn_cli.create_parser(args)
    self.mock_open.assert_called_with(
        cbn_cli.resolve_file_path(self.parser_file_name), 'rb')
    self.mock_make_request.assert_called_once_with(args, url, 'POST', mock.ANY,
                                                   cbn_cli.HTTP_REQUEST_HEADERS)

  def test_get_parser(self):
    cmd_line_args = 'status -i={}'.format(self.config_id)
    url = '{}/tools/cbnParsers/{}'.format(cbn_cli.CHRONICLE_API_V1_URL,
                                          self.config_id)
    self.mock_make_request.return_value = self.parser

    args = cbn_cli.arg_parser().parse_args(cmd_line_args.split())
    cbn_cli.get_parser(args)
    self.mock_make_request.assert_called_once_with(args, url)

  def test_list_parsers(self):
    cmd_line_args = 'list'
    url = '{}/tools/cbnParsers'.format(cbn_cli.CHRONICLE_API_V1_URL)
    self.mock_make_request.return_value = self.parsers

    args = cbn_cli.arg_parser().parse_args(cmd_line_args.split())
    cbn_cli.list_parsers(args)
    self.mock_make_request.assert_called_once_with(args, url)

    # Verify handling no cbnParsers.
    self.mock_make_request.return_value = json.loads('{}')
    with self.assertRaises(SystemExit):
      cbn_cli.list_parsers(args)
    self.mock_make_request.assert_called_with(args, url)

  def test_list_parsers_history(self):
    cmd_line_args = 'history -l={}'.format(self.log_type)
    url = '{}/tools/cbnParsers:listCbnParserHistory?log_type={}'.format(
        cbn_cli.CHRONICLE_API_V1_URL, self.log_type)
    self.mock_make_request.return_value = self.parsers

    args = cbn_cli.arg_parser().parse_args(cmd_line_args.split())
    cbn_cli.list_parsers_history(args)
    self.mock_make_request.assert_called_once_with(args, url)

    # Verify handling no cbnParsers.
    self.mock_make_request.return_value = json.loads('{}')
    with self.assertRaises(SystemExit):
      cbn_cli.list_parsers_history(args)
    self.mock_make_request.assert_called_with(args, url)

  def test_archive_parser(self):
    cmd_line_args = 'archive -i={}'.format(self.config_id)
    url = '{}/tools/cbnParsers/{}:archive'.format(cbn_cli.CHRONICLE_API_V1_URL,
                                                  self.config_id)
    self.mock_make_request.return_value = self.parser

    args = cbn_cli.arg_parser().parse_args(cmd_line_args.split())
    cbn_cli.archive_parser(args)
    self.mock_make_request.assert_called_once_with(args, url, 'POST')

  def test_download_parser_config_id(self):
    cmd_line_args = 'download -i={}'.format(self.config_id)
    url = '{}/tools/cbnParsers/{}'.format(cbn_cli.CHRONICLE_API_V1_URL,
                                          self.config_id)
    self.mock_make_request.return_value = self.parser

    args = cbn_cli.arg_parser().parse_args(cmd_line_args.split())
    with mock.patch('builtins.open', mock.mock_open()) as mock_file:
      cbn_cli.download_parser(args)
    mock_file.assert_called_once_with(mock.ANY, 'a')
    self.mock_make_request.assert_called_once_with(args, url)

  def test_download_parser_log_type(self):
    cmd_line_args = 'download -l={}'.format(self.log_type)
    url = '{}/tools/cbnParsers'.format(cbn_cli.CHRONICLE_API_V1_URL)
    self.mock_make_request.return_value = self.parsers

    args = cbn_cli.arg_parser().parse_args(cmd_line_args.split())
    with mock.patch('builtins.open', mock.mock_open()) as mock_file:
      cbn_cli.download_parser(args)
    mock_file.assert_called_once_with(mock.ANY, 'a')
    self.mock_make_request.assert_called_once_with(args, url)

  def test_parser_errors(self):
    start_date, end_date = '2020-10-10', '2020-10-11'
    cmd_line_args = 'error -l={} -sd={} -ed={}'.\
        format(self.log_type, start_date, end_date)
    url = '{}/tools/cbnParsers:listCbnParserErrors?log_type={}&start_time={}&end_time={}'.\
      format(cbn_cli.CHRONICLE_API_V1_URL, self.log_type, start_date, end_date)
    self.mock_make_request.return_value = json.loads('{}')

    args = cbn_cli.arg_parser().parse_args(cmd_line_args.split())
    cbn_cli.parser_errors(args)
    self.mock_make_request.assert_called_once_with(args, url)

    # Verify command with out passing log_type.
    cmd_line_args = 'error -sd={} -ed={}'.format(start_date, end_date)
    url = '{}/tools/cbnParsers:listCbnParserErrors?log_type={}&start_time={}&end_time={}'.\
      format(cbn_cli.CHRONICLE_API_V1_URL, 'UNSPECIFIED_LOG_TYPE', start_date, end_date)
    args = cbn_cli.arg_parser().parse_args(cmd_line_args.split())
    cbn_cli.parser_errors(args)
    self.mock_make_request.assert_called_with(args, url)

  def test_decode_sample_log(self):
    sample_log = base64.encodebytes(b'start\x9c\x89\xf4end')
    decoded_log = cbn_cli.decode_sample_log(sample_log)
    self.assertEqual('start\udc9c\udc89\udcf4end', decoded_log)

  @parameterized.expand([
      ('download expects either log_type or config_id', 'download'),
      ('download expects only one of log_type or config_id',
       'download -l=a -i=b'),
  ])
  def test_parse_args(self, _, cmd_line):
    with self.assertRaises(SystemExit):
      cbn_cli.arg_parser().parse_args(cmd_line.split())

  def test_main(self):
    cmd_line_args = 'status -i={}'.format(self.config_id)
    url = '{}/tools/cbnParsers/{}'.format(cbn_cli.CHRONICLE_API_V1_URL,
                                          self.config_id)
    self.mock_make_request.return_value = self.parser

    cbn_cli.main(cmd_line_args.split())
    self.mock_make_request.assert_called_once_with(mock.ANY, url)


if __name__ == '__main__':
  unittest.main()
