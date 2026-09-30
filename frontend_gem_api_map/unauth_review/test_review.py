import collections
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from test_mapper import MappingTests
from review_candidates import Review


class ReviewTests(unittest.TestCase):
    def model(self, files, extra_apis=()):
        m = MappingTests.build(self, files)
        for api in extra_apis:
            m.apis.append(api)
            m.api_by_name[api['method']].append(api)
        r = Review.__new__(Review)
        r.m, r.source = m, m.source
        r.api = {a['id']: a for a in m.apis}
        r.tree_cache, r.enriched, r.return_cache, r.callback_cache = {}, {}, {}, {}
        r.gaps, r.touched = [], set()
        return r

    def root(self, r, owner='ThingsController', method='show'):
        return r.m.lookup(owner, method)

    def test_literal_receiver_excludes_colliding_native_type(self):
        r = self.model({'app/controllers/things_controller.rb': '''
class ThingsController
  def show; 'text'.to_s; end
end
'''}, [{'id': 'decimal_to_s', 'namespace': 'BigDecimal', 'method': 'to_s', 'kinds': ['instance']}])
        sites, _, _ = r.trace(self.root(r))
        self.assertEqual(sites[0]['status'], 'rejected')
        self.assertEqual(sites[0]['receiver_inference']['type'], 'String')

    def test_constructor_and_simple_helper_return(self):
        r = self.model({'app/controllers/things_controller.rb': '''
class ThingsController
  def show
    helper.parse('x')
    re = RE2::Regexp.new('x')
    re.match('x')
  end
  def helper; JSON; end
end
'''})
        sites, _, _ = r.trace(self.root(r))
        supported = {i for s in sites for i in s['supported_api_ids']}
        self.assertTrue({'json_parse', 're2_initialize', 're2_match'} <= supported)

    def test_optional_default_does_not_prove_receiver(self):
        r = self.model({'app/controllers/things_controller.rb': '''
class ThingsController
  def show(value = {}); value.merge(a: 1); end
end
'''}, [{'id': 'set_merge', 'namespace': 'CharacterSet', 'method': 'merge', 'kinds': ['instance']}])
        sites, _, _ = r.trace(self.root(r))
        self.assertEqual(sites[0]['status'], 'unresolved')

    def test_unknown_inventory_namespace_stays_unresolved(self):
        r = self.model({'app/controllers/things_controller.rb': '''
class ThingsController
  def show; {}.merge(a: 1); end
end
'''}, [{'id': 'unowned_merge', 'namespace': None, 'method': 'merge', 'kinds': []}])
        sites, _, _ = r.trace(self.root(r))
        self.assertEqual(sites[0]['unresolved_api_ids'], ['unowned_merge'])

    def test_inherited_method_uses_actual_controller_override(self):
        r = self.model({'app/controllers/things_controller.rb': '''
class BaseController
  def show; helper; end
  def helper; JSON.parse('x'); end
end
class ThingsController < BaseController
  def helper; 'no parse'; end
end
'''})
        sites, _, visited = r.trace(self.root(r), context_owner='ThingsController')
        self.assertFalse(any(s['supported_api_ids'] for s in sites))
        self.assertTrue(any('ThingsController' == r.m.units[u]['owner'] for u in visited))

    def test_inline_permission_callback_is_reviewed(self):
        r = self.model({'app/controllers/things_controller.rb': '''
class ThingsController
  before_action -> { check_permission(:manage) }, only: [:show]
  def show; JSON.parse('x'); end
  def check_permission(action); render_404 unless can?(current_user, action); end
end
'''})
        callbacks, _ = r.active_callbacks('ThingsController', 'show')
        self.assertTrue(callbacks[0]['roots'])
        classification, _ = r.auth_review({'class_or_field': 'ThingsController', 'auth': {'evidence': []}}, callbacks)
        self.assertEqual(classification['classification'], 'unknown')

    def test_dynamic_target_is_not_traced(self):
        r = self.model({'app/controllers/things_controller.rb': '''
class ThingsController
  def show; public_send(:helper); end
  def helper; JSON.parse('x'); end
end
'''})
        sites, gaps, _ = r.trace(self.root(r))
        self.assertFalse(any(s['supported_api_ids'] for s in sites))
        self.assertTrue(any(g['kind'] == 'dynamic_dispatch' for g in gaps))


if __name__ == '__main__':
    unittest.main()
