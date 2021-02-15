require "test_helper"

require "rodauth/features/create_account"
require "rodauth/features/verify_account"
require "rodauth/features/login_password_requirements_base"
require "bcrypt"

class ApotonickApiTest < Minitest::Spec
  it "what" do
    DB = Struct.new(:tables) do
      def [](key)
        tables.fetch(key)
      end
    end
    Table = Struct.new(:rows) do
      def insert(row)
        rows << row
        1
      end
    end
    db = DB.new(
      {
        :users => Table.new([])
      }
    )


    api = Class.new do
      def initialize(db)
        @db = db
      end

      attr_reader :db


      include Rodauth::FEATURES[:create_account]
      include Rodauth::FEATURES[:login_password_requirements_base] # {#password_hash} and friends.


      def login_column # DISCUSS: add keyword arg?
        :email
      end

      def skip_status_checks? # DISCUSS: this is done by the workflow
        true
      end

      def accounts_table;     :users; end
      def account_id_column;  :id; end


      def raises_uniqueness_violation?
        yield
        false
      end

      def account_password_hash_column
        :password_hashed
      end


      def save_account(account:)
        @account = account # FIXME: mutable state on the instance, not good.
        super()
      end
      attr_reader :account
    end.new(db)



    account = api.new_account("bla") # Rodauth uses {login} which is any unique string. Make email check in web.ui.

    password = "verysecret"
    password_confirm = "verysecret"

    api.set_new_account_password(password)


# if create_account_set_password?
    if  password != password_confirm # FIXME: this is "logic" copied from {create_account:54}, we put that in {lib.CreateAccount}
      raise # Rodauth throws an error here
    else
      # we skip password hash
      pp api.save_account(account: account)
      pp account
        # => { :email=>"bla",
        #      :password_hashed=>
        #       "$2a$12$YBwAo1wNThzSNKzqUVjqkOvHhr/2ZcRFX/jPr784qVd1VTh26fywa",
        #      :id=>1}

    end
  end
end
