# -*- coding: utf-8 -*-
from itertools import product

from nose.tools import assert_equal, assert_set_equal
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


@parameterized(["ascii", "latin-1", "UTF-8"])
def test_text_attachment_only_ascii_characters(encoding):
    subject = "This is my subject"
    text = "This is my email"
    attachment = generate_text_attachment("This is my attachment", encoding)

    perform_encoding_test(subject, text, encoding, original_attachments=[attachment])


@parameterized(["latin-1", "UTF-8"])
def test_text_attachment_umlaut(encoding):
    subject = "This is my subject"
    text = "This is my email"
    attachment = generate_text_attachment("Gänsefüßchen", encoding)

    perform_encoding_test(subject, text, encoding, original_attachments=[attachment])


@parameterized(["latin-1", "UTF-8"])
def test_text_attachment_accent(encoding):
    subject = "This is my subject"
    text = "This is my email"
    attachment = generate_text_attachment("Liberté, égalité, fraternité", encoding)

    perform_encoding_test(subject, text, encoding, original_attachments=[attachment])


@nottest
def perform_encoding_test(original_subject, original_text, encoding, body_type="text", original_attachments=[]):
    msg = generate_message(original_subject, original_text, encoding, body_type, original_attachments)

    result_header, result_text, result_attachments = parse_message(msg)
    result_subject = pyzmail.parse.decode_mail_header(result_header["Subject"])

    assert_equal(original_subject, result_subject)
    assert_equal(original_text, result_text)

    original_attachments = [att[0] for att in original_attachments]      # first entry in attachment tuple contains text
    assert_set_equal(set(original_attachments), set(result_attachments)) # don't care about ordering of attachments


def generate_message(subject, text, encoding, body_type, attachments):
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
                                            attachments=attachments)
    payload = [p.encode() for p in payload.split("\n")]
    return payload


def generate_text_attachment(text, encoding):
    return text, "text", "plain", "name.txt", encoding