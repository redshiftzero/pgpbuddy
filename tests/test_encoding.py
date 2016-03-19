# -*- coding: utf-8 -*-
from itertools import product

from nose.tools import assert_equal
from nose.tools import nottest
from nose_parameterized import parameterized
import pyzmail

from pgpbuddy.fetch import parse_message


@parameterized(product(["ascii", "latin-1", "UTF-8"], ["text", "html"]))
def test_only_ascii_characters(encoding, body_type):
    subject = "This is my subject"
    text = "This is my email text"
    perform_encoding_test(subject, text, encoding, body_type)


@parameterized(product(["latin-1", "UTF-8"], ["text", "html"]))
def test_umlaut_text(encoding, body_type):
    subject = "This is my subject"
    text = "Gänsefüßchen"
    perform_encoding_test(subject, text, encoding, body_type)


@parameterized(["latin-1", "UTF-8"])
def test_umlaut_subject(encoding):
    subject = "Gänsefüßchen"
    text = "This is my email text"
    perform_encoding_test(subject, text, encoding)


@parameterized(product(["latin-1", "UTF-8"], ["text", "html"]))
def test_accent_text(encoding, body_type):
    subject = "This is my subject"
    text = "Liberté, égalité, fraternité"
    perform_encoding_test(subject, text, encoding, body_type)


@parameterized(["latin-1", "UTF-8"])
def test_accent_subject(encoding):
    subject = "Liberté, égalité, fraternité"
    text = "This is my email"
    perform_encoding_test(subject, text, encoding)


def test_attachment():
    attachment = [("This is the text content of my attachment", "text", "plain", "name.txt")]
    #assert(False)
    pass


@nottest
def perform_encoding_test(original_subject, original_text, encoding, body_type="text"):
    msg = generate_message(original_subject, original_text, encoding, body_type)

    result_header, result_text, result_attachments = parse_message(msg)
    result_subject = pyzmail.parse.decode_mail_header(result_header["Subject"])

    assert_equal(original_subject, result_subject)
    assert_equal(original_text, result_text)
    assert_equal(len(result_attachments), 0)


def generate_message(subject, text, encoding, body_type):
    if body_type == "html":
        html = (text, encoding)
        text = None
    elif body_type == "text":
        text = (text, encoding)
        html = None
    else:
        raise NotImplementedError()

    payload, _, _, _ = pyzmail.compose_mail(sender=(u'Me', 'me@foo.com'),
                                            recipients=[(u'Her', 'her@bar.com')],
                                            subject=subject,
                                            default_charset=encoding,
                                            text=text,
                                            html=html,
                                            attachments=[])
    payload = [p.encode() for p in payload.split("\n")]
    return payload
