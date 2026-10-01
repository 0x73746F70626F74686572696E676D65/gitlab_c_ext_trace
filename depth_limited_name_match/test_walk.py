"""Parser fixtures are inspected as text; none of their Ruby is executed."""
import tempfile
import unittest
from pathlib import Path

from walk import Walker, expression_kind


class StaticWalkChecks(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        (self.root / 'app/services').mkdir(parents=True)
        (self.root / 'lib').mkdir()
        (self.root / 'app/services/entry.rb').write_text('''class Entry
  def run(input)
    helper
    value = input
    worker = Worker.new
    worker.process(value)
    send(:parse) { hidden_parse(input) }
    value[0] = "fixed"
    value.status = input
  end
  def helper
    Worker.new.process("literal")
  end
  def unrelated
    forbidden(input)
  end
end
''')
        (self.root / 'app/services/worker.rb').write_text('''class Worker
  def initialize; end
  def process(input)
    parse(input)
  end
end
''')
        self.w = Walker(self.root)
        self.w.load('app/services/entry.rb')

    def tearDown(self):
        self.tmp.cleanup()

    def test_scopes_bare_calls_and_dynamic_branch(self):
        unit = self.w.lookup('Entry', 'run', False, 'ce')
        calls = self.w.calls(unit)
        names = [c[1] for c in calls]
        self.assertIn('helper', names)
        self.assertIn('send', names)
        self.assertIn('[]=', names)
        self.assertIn('status=', names)
        self.assertNotIn('hidden_parse', names)
        self.assertNotIn('forbidden', names)
        self.assertNotIn('input', names)
        self.assertNotIn('value', names)
        store = next(c for c in calls if c[1] == '[]=')
        self.assertEqual([n.text.decode() for n in store[3]], ['0', '"fixed"'])

    def test_local_new_binding_and_no_unknown_receiver_guess(self):
        unit = self.w.lookup('Entry', 'run', False, 'ce')
        call = next(c for c in self.w.calls(unit) if c[1] == 'process')
        result = self.w.target(unit, *call[:3], 'ce')
        self.assertEqual((result['owner'], result['name']), ('Worker', 'process'))
        call = next(c for c in self.w.calls(unit) if c[1] == 'status=')
        self.assertIsNone(self.w.target(unit, *call[:3], 'ce'))
        self.assertEqual(set(self.w.files), {'app/services/entry.rb', 'app/services/worker.rb'})

    def test_literal_and_identifier(self):
        unit = self.w.lookup('Entry', 'helper', False, 'ce')
        call = next(c for c in self.w.calls(unit) if c[1] == 'process')
        self.assertEqual(expression_kind(call[3][0]), 'literal')
        unit = self.w.lookup('Worker', 'process', False, 'ce')
        call = next(c for c in self.w.calls(unit) if c[1] == 'parse')
        self.assertEqual(expression_kind(call[3][0]), 'identifier')

    def test_super_and_assignment_receiver(self):
        (self.root / 'app/services/other.rb').write_text('''class Other
  def run(input)
    super(input)
    Worker.new.process(input).status = -1
  end
end
''')
        self.w.load('app/services/other.rb')
        unit = self.w.lookup('Other', 'run', False, 'ce')
        calls = self.w.calls(unit)
        self.assertEqual([c[1] for c in calls].count('super'), 1)
        self.assertIn('process', [c[1] for c in calls])
        setter = next(c for c in calls if c[1] == 'status=')
        self.assertEqual(expression_kind(setter[3][0]), 'literal')


if __name__ == '__main__':
    unittest.main()
