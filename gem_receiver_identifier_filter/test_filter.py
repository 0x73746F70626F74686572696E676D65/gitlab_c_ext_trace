"""Static Ruby text fixtures; no target or fixture Ruby is executed."""
import json
import tempfile
import unittest
from pathlib import Path

from filter import SourceFilter


class ReceiverAndArgumentChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / 'app/services').mkdir(parents=True)
        (self.root / 'lib').mkdir()
        (self.root / 'app/services/example.rb').write_text('''class Example
  Parser = Date
  def direct(raw)
    Date::parse(raw)
    Oj.parse(raw)
    Parser.parse(raw)
    Date.parse("fixed")
    Date.parse(raw.bytesize)
    Date.parse(raw + suffix)
    Date.parse
    parse(raw)
    self.parse(raw)
  end
  def local(raw)
    parser = Oj
    parser.parse(raw)
  end
  def constructed(raw)
    reader = StringIO.new(raw)
    reader.read(raw)
  end
  def unknown(parser, raw)
    parser.parse(raw)
  end
  def reassigned(raw)
    parser = Oj
    parser = something_else
    parser.parse(raw)
  end
  def shadowed(raw)
    parser = Oj
    items.each { |parser| parser.parse(raw) }
  end
  def other_block(raw)
    items.each { parser = Oj }
    parser.parse(raw)
  end
  def ambiguous(raw)
    Date.parse(raw); Oj.parse(raw)
  end
end
''')
        self.sf = SourceFilter(self.root, {'Date': 'date', 'Oj': 'oj', 'StringIO': 'stringio'}, {})
        self.info = self.sf.load('app/services/example.rb')

    def tearDown(self):
        self.tmp.cleanup()

    def row(self, body, receiver, expression, gem='date'):
        unit = next(u for u in self.info['definitions'] if u['name'] == body)
        call = next(c for c in self.sf.syntax.calls(unit)
                    if (c[2].text.decode() if c[2] else '') == receiver
                    and (c[3][0].text.decode() if c[3] else '') == expression)
        return {'file': unit['file'], 'line': str(call[0].start_point.row + 1), 'ruby_method': call[1],
                'argument_index': '0', 'gem': gem, 'expression': expression,
                'expression_kind': 'literal' if expression == '"fixed"' else 'identifier',
                'call_chain': json.dumps([{'file': unit['file'], 'line': unit['line'], 'method': 'Example#' + body}])}

    def test_direct_gem_and_constant_alias(self):
        for receiver in ['Date', 'Parser']:
            self.assertEqual(self.sf.decide(self.row('direct', receiver, 'raw'))[0], 'kept')
        self.assertEqual(self.sf.decide(self.row('direct', 'Oj', 'raw'))[0], 'receiver')

    def test_identifier_only_after_receiver(self):
        for expr in ['"fixed"', 'raw.bytesize', 'raw + suffix', '']:
            self.assertEqual(self.sf.decide(self.row('direct', 'Date', expr))[0], 'argument')

    def test_missing_receiver_self_and_unknown_local(self):
        for receiver in ['', 'self']:
            self.assertEqual(self.sf.decide(self.row('direct', receiver, 'raw'))[0], 'receiver')
        self.assertEqual(self.sf.decide(self.row('unknown', 'parser', 'raw', 'oj'))[0], 'receiver')

    def test_resolved_local_and_constructor(self):
        self.assertEqual(self.sf.decide(self.row('local', 'parser', 'raw', 'oj'))[0], 'kept')
        self.assertEqual(self.sf.decide(self.row('constructed', 'reader', 'raw', 'stringio'))[0], 'kept')

    def test_reassignment_shadowing_and_ambiguous_saved_site(self):
        for body in ['reassigned', 'shadowed', 'other_block', 'ambiguous']:
            receiver = 'Date' if body == 'ambiguous' else 'parser'
            self.assertEqual(self.sf.decide(self.row(body, receiver, 'raw', 'date' if body == 'ambiguous' else 'oj'))[0], 'receiver')


if __name__ == '__main__':
    unittest.main()
