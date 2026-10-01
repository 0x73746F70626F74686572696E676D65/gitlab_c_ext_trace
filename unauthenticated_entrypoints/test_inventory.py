import contextlib, io, json, subprocess, tempfile, unittest
from pathlib import Path
from build_inventory import Index, Routes, AuthCheck, GrapeInventory, GraphqlInventory


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.put('app/policies/global_policy.rb','class GlobalPolicy; end')
        self.put('config/authz/roles/public_anonymous.yml','project:\n  raw_permissions: [read_project, read_code]\ngroup:\n  raw_permissions: [read_group]\n')
        self.put('app/controllers/application_controller.rb','''class ApplicationController
 before_action :authenticate_user!
 def authenticate_user!; head(:unauthorized) unless current_user; end
end''')
        self.put('config/routes.rb','Rails.application.routes.draw do; end')

    def tearDown(self):self.temp.cleanup()
    def put(self,path,text):
        p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(text)
    def index(self):
        for cmd in [['git','init','-q'],['git','add','.'],['git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture']]:subprocess.run(cmd,cwd=self.root,check=True,stdout=subprocess.DEVNULL)
        with contextlib.redirect_stdout(io.StringIO()):idx=Index(self.root,None,self.root/'no_baseline')
        return idx,AuthCheck(idx)
    def routes(self,idx):return Routes(idx).run()
    def test_draw_aliases_and_controller_resolution(self):
        self.put('app/controllers/oauth/dynamic_registrations_controller.rb','class Oauth::DynamicRegistrationsController < ApplicationController; def create; end; end')
        self.put('config/routes.rb',"""Rails.application.routes.draw do
 def draw_all_routes
  post '/oauth/register' => 'oauth/dynamic_registrations#create'
 end
 draw_all_routes
 scope path: '/o/:organization_path' do; draw_all_routes; end
end""")
        idx,_=self.index();rs=self.routes(idx)
        ce=[r for r in rs if r['edition']=='ce'];self.assertEqual({'/oauth/register','/o/:organization_path/oauth/register'},{r['path'] for r in ce});self.assertTrue(all(r['controller']=='Oauth::DynamicRegistrationsController' for r in ce))
    def test_resources_nested_member_collection_and_only(self):
        self.put('config/routes.rb',"""Rails.application.routes.draw do
 namespace :projects do
  resources :issues, only: [:show] do
   member do; get :preview; end
   collection do; get :search; end
   resources :notes, only: [:show]
  end
 end
end""")
        idx,_=self.index();rs=[r for r in self.routes(idx) if r['edition']=='ce']
        self.assertEqual({'/projects/issues/:id','/projects/issues/:id/preview','/projects/issues/search','/projects/issues/:issue_id/notes/:id'},{r['path'] for r in rs})
        self.assertTrue(all(r['controller'] in {'Projects::IssuesController','Projects::NotesController'} for r in rs))
    def test_static_loop_interpolation(self):
        self.put('config/routes.rb',"""Rails.application.routes.draw do
 %w[one two].each do |action|; get "/#{action}", to: 'things#show'; end
end""")
        idx,_=self.index();self.assertEqual({'/one','/two'},{r['path'] for r in self.routes(idx) if r['edition']=='ce'})
    def test_skip_does_not_hide_replacement_login(self):
        self.put('app/controllers/public_controller.rb','''class PublicController < ApplicationController
 skip_before_action :authenticate_user!
 before_action :require_verification_user!
 def require_verification_user!; head(:unauthorized) unless current_user; end
 def show; render plain: 'ok'; end
end''')
        self.put('config/routes.rb',"Rails.application.routes.draw do; get '/public', to: 'public#show'; end")
        idx,auth=self.index();r=self.routes(idx)[0];self.assertEqual('authenticated',auth.rails(r)['classification'])
    def test_guest_guarded_callback_is_optional(self):
        self.put('app/controllers/public_controller.rb','''class PublicController < ApplicationController
 skip_before_action :authenticate_user!
 before_action :check_user
 def check_user; return unless current_user; authenticate_user!; end
 def show; render plain: 'ok'; end
end''')
        self.put('config/routes.rb',"Rails.application.routes.draw do; get '/public', to: 'public#show'; end")
        idx,auth=self.index();self.assertEqual('unauthenticated',auth.rails(self.routes(idx)[0])['classification'])
    def test_conditional_skip_stays_unresolved(self):
        self.put('app/controllers/public_controller.rb','''class PublicController < ApplicationController
 skip_before_action :authenticate_user!, if: :opaque_setting?
 def show; render plain: 'ok'; end
end''')
        self.put('config/routes.rb',"Rails.application.routes.draw do; get '/public', to: 'public#show'; end")
        idx,auth=self.index();self.assertEqual('unknown',auth.rails(self.routes(idx)[0])['classification'])
    def test_inherited_method_dispatch_uses_actual_controller(self):
        self.put('app/controllers/public_controller.rb','''class PublicController < ApplicationController
 skip_before_action :authenticate_user!
 before_action :require_gate
 def require_gate; authenticate!; end
 def show; render plain: 'ok'; end
end''')
        self.put('config/routes.rb',"Rails.application.routes.draw do; get '/public', to: 'public#show'; end")
        idx,auth=self.index();self.assertEqual('authenticated',auth.rails(self.routes(idx)[0])['classification'])
    def test_mount_version_precedes_namespace_and_auth_inherits(self):
        self.put('lib/api/api.rb','''module API
 class API < Grape::API::Instance
  prefix :api
  version 'v4', using: :path
  before do; authenticate!; end
  namespace :groups do
   namespace ':id' do; mount ::API::Items; end
  end
 end
 class Items < Grape::API::Instance
  resource :items do; get do; present []; end; end
 end
end''')
        self.put('config/routes.rb',"Rails.application.routes.draw do; mount ::API::API => '/'; end")
        idx,auth=self.index()
        rs=GrapeInventory(idx,auth,self.routes(idx)).run();self.assertEqual({'/api/v4/groups/:id/items'},{r['path'] for r in rs});self.assertTrue(all(r['auth']['classification']=='authenticated' for r in rs))
    def test_around_filter_cannot_be_skipped_as_non_auth(self):
        self.put('app/controllers/public_controller.rb','''class PublicController < ApplicationController
 skip_before_action :authenticate_user!
 around_action do; authenticate!; yield; end
 def show; render plain: 'ok'; end
end''')
        self.put('config/routes.rb',"Rails.application.routes.draw do; get '/public', to: 'public#show'; end")
        idx,auth=self.index();self.assertEqual('authenticated',auth.rails(self.routes(idx)[0])['classification'])
    def test_action_selector_does_not_apply_create_auth_to_new(self):
        self.put('app/controllers/public_controller.rb','''class PublicController < ApplicationController
 skip_before_action :authenticate_user!
 before_action :authenticate!, if: -> { action_name == 'create' && two_factor_enabled? }
 def new; render plain: 'ok'; end
end''')
        self.put('config/routes.rb',"Rails.application.routes.draw do; get '/new', to: 'public#new'; end")
        idx,auth=self.index();self.assertEqual('unauthenticated',auth.rails(self.routes(idx)[0])['classification'])
    def test_anonymous_read_role_does_not_authorize_writes(self):
        idx,auth=self.index();self.assertEqual('conditional_anonymous',auth.permissions('read_project',{})['classification']);self.assertEqual('authenticated',auth.permissions('admin_project',{})['classification']);self.assertEqual('unknown',auth.permissions('novel_permission',{})['classification'])

    def test_grape_segments_and_route_params_are_in_paths_and_hook_scopes(self):
        self.put('lib/api/api.rb','''module API
 class API < Grape::API::Instance
  prefix :api; version 'v4', using: :path
  resource :projects do
   segment ':id/boards' do
    before do; authenticate!; end
    route_param :board_id do; get '/' do; present []; end; end
   end
   get '/' do; present []; end
  end
 end
end''')
        self.put('config/routes.rb',"Rails.application.routes.draw do; mount ::API::API => '/'; end")
        idx,auth=self.index();rs=[r for r in GrapeInventory(idx,auth,self.routes(idx)).run() if r['edition']=='ce']
        self.assertEqual({'/api/v4/projects','/api/v4/projects/:id/boards/:board_id'},{r['path'] for r in rs})
        self.assertEqual({'/api/v4/projects':'unauthenticated','/api/v4/projects/:id/boards/:board_id':'authenticated'},{r['path']:r['auth']['classification'] for r in rs})

    def test_with_options_condition_is_inherited_by_callbacks(self):
        self.put('app/controllers/public_controller.rb','''class PublicController < ApplicationController
 skip_before_action :authenticate_user!
 with_options if: -> { current_user.present? } do
  before_action :authenticate!
 end
 def show; render plain: 'ok'; end
end''')
        self.put('config/routes.rb',"Rails.application.routes.draw do; get '/public', to: 'public#show'; end")
        idx,auth=self.index();self.assertEqual('unauthenticated',auth.rails(self.routes(idx)[0])['classification'])

    def test_super_and_dynamic_auth_dispatch_are_not_ignored(self):
        self.put('app/controllers/base_controller.rb','''class BaseController < ApplicationController
 skip_before_action :authenticate_user!
 def show; authenticate!; end
end''')
        self.put('app/controllers/public_controller.rb','''class PublicController < BaseController
 def show; super; end
 def dynamic; public_send(params[:guard]); end
end''')
        self.put('config/routes.rb',"Rails.application.routes.draw do; get '/public', to: 'public#show'; get '/dynamic', to: 'public#dynamic'; end")
        idx,auth=self.index();rs={r['path']:auth.rails(r) for r in self.routes(idx) if r['edition']=='ce'}
        self.assertEqual('authenticated',rs['/public']['classification']);self.assertEqual('unknown',rs['/dynamic']['classification'])

    def test_graphql_connection_path_and_orphan_field(self):
        self.put('app/graphql/types/query_type.rb','''module Types
 class QueryType
  field :things, Types::ThingType.connection_type, null: false
 end
 class ThingType
  field :title, GraphQL::Types::String, null: false
  def title; 'ok'; end
 end
 class OrphanType
  field :invisible, GraphQL::Types::String, null: true
 end
end''')
        idx,auth=self.index();rs=GraphqlInventory(idx,auth).run()
        self.assertIn(['things','nodes','title'],[r['graphql']['schema_path'] for r in rs]);self.assertNotIn('invisible',[r['graphql']['field'] for r in rs])


if __name__=='__main__':unittest.main()
