# -*- coding: utf-8 -*-

from nose.tools import assert_equal
from nose.tools import nottest
import pyzmail

from pgpbuddy.fetch import parse_message


def test_ascii():
    subject = "This is my subject"
    text = "This is my email text"
    perform_encoding_test(subject, text, "ascii")


def test_utf8():
    subject = "This is my subject"
    text = "This is my email text"
    perform_encoding_test(subject, text, "UTF-8")


def test_umlaut_text_utf8():
    subject = "This is my subject"
    text = "Gänsefüßchen"
    perform_encoding_test(subject, text, "UTF-8")


def test_umlaut_subject_utf8():
    subject = "Gänsefüßchen"
    text = "This is my email text"
    perform_encoding_test(subject, text, "UTF-8")


def test_umlaut_text_latin1():
    subject = "This is my subject"
    text = "Gänsefüßchen"
    perform_encoding_test(subject, text, "latin-1")


def test_umlaut_subject_latin1():
    subject = "This is my subject"
    text = "Gänsefüßchen"
    perform_encoding_test(subject, text, "latin-1")


def test_accent_subject_latin1():
    subject = "Liberté, égalité, fraternité"
    text = "This is my email"
    perform_encoding_test(subject, text, "latin-1")


def test_accent_text_latin1():
    subject = "This is my subject"
    text = "Liberté, égalité, fraternité"
    perform_encoding_test(subject, text, "latin-1")


@nottest
def perform_encoding_test(original_subject, original_text, encoding):
    msg = generate_message(original_subject, original_text, encoding)

    result_header, result_text, result_attachments = parse_message(msg)
    result_subject = pyzmail.parse.decode_mail_header(result_header["Subject"])

    assert_equal(original_subject, result_subject)
    assert_equal(original_text, result_text)
    assert_equal(len(result_attachments), 0)


def generate_message(subject, text, encoding):
    payload, _, _, _ = pyzmail.compose_mail((u'Me', 'me@foo.com'), [(u'Her', 'her@bar.com')],
                                            subject, encoding, (text, encoding))
    payload = [p.encode() for p in payload.split("\n")]
    return payload
