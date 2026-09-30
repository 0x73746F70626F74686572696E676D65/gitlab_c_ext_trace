import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from map_frontend import Mapper


class MappingTests(unittest.TestCase):
    def build(self, files):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        for name, source in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(source)
        inventory = root / 'apis.json'
        inventory.write_text(json.dumps([
            {'id': 'json_parse', 'namespace': 'JSON', 'method': 'parse', 'kinds': ['singleton'], 'gem': 'oj'},
            {'id': 'other_parse', 'namespace': 'OtherGem', 'method': 'parse', 'kinds': ['instance'], 'gem': 'other'},
            {'id': 'unowned_parse', 'namespace': None, 'method': 'parse', 'kinds': [], 'gem': 'unowned'},
            {'id': 're2_initialize', 'namespace': 'RE2::Regexp', 'method': 'initialize', 'kinds': ['instance'], 'gem': 're2'},
            {'id': 're2_match', 'namespace': 'RE2::Regexp', 'method': 'match', 'kinds': ['instance'], 'gem': 're2'}]))
        with patch('map_frontend.git', side_effect=lambda root, *args: '\0'.join(files) if args[0] == 'ls-files' else 'testsha'):
            m = Mapper(root, inventory, root / 'out')
            m.parse()
        m.finish_entries()
        m.prepare_units()
        return m

    def actions(self, m):
        return {e['action']: e for e in m.entries if e['type'] == 'rails_action' and e['class_or_field'] == 'ThingsController'}

    def test_rails_auth_selectors_and_visibility(self):
        m = self.build({'app/controllers/things_controller.rb': '''
class ApplicationController
  before_action :authenticate_user!
end
class ThingsController < ApplicationController
  skip_before_action :authenticate_user!, only: %i[show maybe]
  before_action :authenticate_user!, only: [:maybe], if: :enabled?
  def show; JSON.parse('x'); end
  def edit; JSON.parse('x'); end
  def maybe; JSON.parse('x'); end
  private def hidden; JSON.parse('x'); end
end
'''})
        a = self.actions(m)
        self.assertNotIn('hidden', a)
        self.assertEqual(m.auth(a['show'])[0], 'unauthenticated')
        self.assertEqual(m.auth(a['edit'])[0], 'authenticated')
        self.assertEqual(m.auth(a['maybe'])[0], 'unknown')

    def test_helper_depth_and_alias_confidence(self):
        m = self.build({'app/controllers/things_controller.rb': '''
class ThingsController
  J = JSON
  def show
    first
    J.parse('x')
    unknown.parse('x')
    r = RE2::Regexp.new('x')
    r.match('x')
  end
  private
  def first; second; end
  def second; JSON.parse('x'); third; end
  def third; JSON.parse('x'); end
end
'''})
        e = m.map_entry(self.actions(m)['show'])
        matches = e['matches']
        self.assertTrue(any(x['confidence'] == 'direct' and x['api_ids'] == ['json_parse'] for x in matches))
        self.assertTrue(any(x['confidence'] == 'helper' and x['hop_depth'] == 2 for x in matches))
        self.assertTrue(any(x['confidence'] == 'name-only' and len(x['api_ids']) == 3 for x in matches))
        self.assertTrue(any(x['api_ids'] == ['re2_match'] and x['qualified'] for x in matches))
        self.assertTrue(any(x['api_ids'] == ['re2_initialize'] and x['qualified'] for x in matches))
        self.assertTrue(m.gaps['helper_depth_cutoff'])
        self.assertFalse(any('third' in hop['target'] for x in matches for hop in x['helper_path']))

    def test_dynamic_target_is_not_followed(self):
        m = self.build({'app/controllers/things_controller.rb': '''
class ThingsController
  def show; public_send(:hidden); end
  private
  def hidden; JSON.parse('x'); end
end
'''})
        e = m.map_entry(self.actions(m)['show'])
        self.assertFalse(e['matches'])
        self.assertEqual(len(m.gaps['dynamic_dispatch']), 1)

    def test_unknown_namespace_is_not_qualified(self):
        m = self.build({'app/controllers/things_controller.rb': '''
class ThingsController
  def show; thing.parse('x'); end
end
'''})
        e = m.map_entry(self.actions(m)['show'])
        self.assertTrue(e['matches'])
        self.assertFalse(e['qualified_matched_api_ids'])

    def test_mount_mutation_and_module_functions(self):
        m = self.build({'app/controllers/things_controller.rb': '''
module Utility
  module_function
  def parse_input; JSON.parse('x'); end
end
class ThingsController
  def show; Utility.parse_input; end
end
''', 'app/graphql/types/mutation_type.rb': '''
module Types
  class MutationType
    mount_mutation ::Mutations::DoThing
  end
end
''', 'app/graphql/mutations/do_thing.rb': '''
module Mutations
  class DoThing
    graphql_name 'DoThing'
    def resolve; JSON.parse('x'); end
  end
end
'''})
        e = m.map_entry(self.actions(m)['show'])
        self.assertTrue(any(x['confidence'] == 'helper' for x in e['matches']))
        mutation = next(e for e in m.entries if e['type'] == 'graphql_mutation')
        self.assertEqual(mutation['graphql_name'], 'DoThing')
        self.assertTrue(m.map_entry(mutation)['qualified_matched_api_ids'])

    def test_resources_in_route_method_and_empty_only(self):
        m = self.build({'config/routes.rb': '''
def draw_all_routes
  namespace :admin do
    resources :things, only: %i[index show]
    resources :skips, only: []
  end
end
'''})
        self.assertEqual({r['action'] for r in m.routes}, {'index', 'show'})
        self.assertTrue(all(r['controller'] == 'admin/things' for r in m.routes))
        self.assertEqual(len(m.routes), 2)

    def test_rack_builder_registration_inside_method(self):
        m = self.build({'lib/server.rb': '''
class Server
  def rack_app
    Rack::Builder.app do
      run ->(env) { JSON.parse(env['x']) }
    end
  end
end
'''})
        run = next(e for e in m.entries if e['type'] == 'http_registration' and e['action'] == 'run')
        self.assertTrue(m.map_entry(run)['qualified_matched_api_ids'])

    def test_route_auth_scope(self):
        m = self.build({'config/routes.rb': '''
authenticate :user do
  get '/things', to: 'things#show'
end
''', 'app/controllers/things_controller.rb': '''
class ThingsController
  def show; JSON.parse('x'); end
end
'''})
        self.assertEqual(m.auth(self.actions(m)['show'])[0], 'authenticated')

    def test_multiline_call_location(self):
        m = self.build({'app/controllers/things_controller.rb': '''
class ThingsController
  def show
    JSON
      .parse('x')
  end
end
'''})
        e = m.map_entry(self.actions(m)['show'])
        self.assertEqual(e['matches'][0]['line'], 5)

    def test_grape_scoped_auth_and_graphql_resolver(self):
        m = self.build({
            'lib/api/things.rb': '''
module API
  class Things
    resources :things do
      before { authenticate! }
      get ':id' do
        JSON.parse('x')
      end
    end
    get 'outside' do
      JSON.parse('x')
    end
  end
end
''', 'app/graphql/resolvers/thing_resolver.rb': '''
module Resolvers
  class ThingResolver
    def resolve; JSON.parse('x'); end
  end
end
''', 'app/graphql/types/query_type.rb': '''
module Types
  class QueryType
    field :thing, resolver: ::Resolvers::ThingResolver, authorize: :read_thing
  end
end
'''})
        grapes = [e for e in m.entries if e['type'] == 'grape_endpoint']
        self.assertEqual([m.auth(e)[0] for e in grapes], ['authenticated', 'unknown'])
        query = next(e for e in m.entries if e['type'] == 'graphql_query')
        self.assertEqual(m.auth(query)[0], 'unknown')
        self.assertTrue(m.map_entry(query)['qualified_matched_api_ids'])


if __name__ == '__main__':
    unittest.main()
