"""
Entry point for Slack processing in AWS Lambda.

This lambda_handler handles the url_verification message for the Slack API
handshake.
"""

import functools
import logging
import json
import os

SLACK_APP_TOKEN = os.environ['SLACK_APP_TOKEN']


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def _create_response(status_code, body=None, headers=None, base64=False):
    if body:
        body = json.dumps(body)
    headers = headers or {}

    return {
        'isBase64Encoded': base64,
        'body': body,
        'statusCode': status_code,
        'headers': headers
    }


bad_request = functools.partial(_create_response, status_code=400)
forbidden = functools.partial(_create_response, status_code=403)
ok_response = functools.partial(_create_response, status_code=200)


def lambda_handler(event: dict, context):
    """Handle the Slack request and answer the challenge."""
    logger.info("Received event: %s", json.dumps(event))

    if 'body' not in event:
        return bad_request(body="No 'body' found in request.")

    slack_message = json.loads(event['body'])
    if 'token' not in slack_message:
        return bad_request(body="No 'token' found in request.")

    if slack_message['token'] != SLACK_APP_TOKEN:
        return forbidden(body="Bad token.")

    if slack_message['type'] == 'url_verification':
        if 'challenge' not in slack_message:
            return bad_request(body="'challenge' needed in url_verification.")
        # Handle the url_verification message inline
        # We just want to return the challenge here so there's no need to
        # invoke another Lambda for processing
        return ok_response(body={'challenge': slack_message['challenge']})

    # TODO Forward the request to the next lambda function

    return ok_response()
