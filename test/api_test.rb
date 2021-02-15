require "test_helper"

require "rodauth/features/base"
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
        puts "@@@@@ INSERT: #{row.inspect}"
        rows << row
        1
      end

      def where(options)
        puts "WHERE: @@@@@ #{options.inspect}"

        column_name = options.keys.first
        value = options[column_name]

        set = rows.find_all { |row| row[column_name] == value }

        # return rows[0] if options[:id] == 1
        return self if set.empty?
        return Gettable.new(set)
        # return []  # fixme: USE REAL SEQUEL

      end

      def empty?
        rows.empty?
      end

      class Gettable
        def initialize(set)
          @set = set
        end

        def get(key)
          # raise key.inspect
          @set[0][key]
        end
      end
    end
    db = DB.new(
      {
        :users => Table.new([]),
        :account_verification_keys => Table.new([]),
      }
    )


    api = Class.new do
      def initialize(db)
        @db = db
      end

      attr_reader :db


      # include Rodauth::FEATURES[:create_account]
      include Rodauth::FEATURES[:create_account]
      include Rodauth::FEATURES[:verify_account]
      include Rodauth::FEATURES[:login_password_requirements_base] # {#password_hash} and friends.


      def login_column # DISCUSS: add keyword arg?
        :email
      end

      def skip_status_checks? # DISCUSS: this is done by the workflow
        true
      end

      def accounts_table;           :users; end
      # def verify_account_table;     :users; end
      def account_id_column;        :id; end

      def random_key
        Class.new do # FIXME: we don't want all methods from Base!
          include Rodauth::FEATURES[:base]
        end.new(1).send(:random_key)
      end


      def raises_uniqueness_violation?
        yield
        false
      end
      def raised_uniqueness_violation
        yield
      end

      def transaction
        yield
      end

      def send_verify_account_email # FIXME: for now, we want that done manually in Tyrant.
      end

      def account_password_hash_column
        :password_hashed
      end

      # needed in {verify_account.rb:195:in `new_account'}
      def account_from_login(*) # FIXME: this should be changed in Roda, this is called unnecessarily.
        @account
      end
      def account_id
        @account.fetch(:id)
      end


      def save_account(account:)
        @account = account # FIXME: mutable state on the instance, not good.
        super()
      end
      attr_reader :account
    end.new(db)


    # For {Create account} we need {:login}, {:password}, {:password_confirm}
    # UI does email check, also uniqueness
    #
    # TODO: use all in {password_requirements}

    account = api.new_account("bla") # Rodauth uses {login} which is any unique string. Make email check in web.ui.

    password = "verysecret"
    password_confirm = "verysecret"

    api.set_new_account_password(password)


# if create_account_set_password?
    if password != password_confirm # FIXME: this is "logic" copied from {create_account:54}, we put that in {lib.CreateAccount}
      raise # Rodauth throws an error here
    else
      # we skip password hash
      pp api.save_account(account: account)
      pp account
        # => { :email=>"bla",
        #      :password_hashed=>
        #       "$2a$12$YBwAo1wNThzSNKzqUVjqkOvHhr/2ZcRFX/jPr784qVd1VTh26fywa",
        #      :id=>1}
  # account created
      assert_equal 60, db[:users].rows[0][:password_hashed].size


      # this usually happens via a {after_create_account} hook
      api.setup_account_verification # FIXME: also sends email
      pp db[:users]
      pp db[:account_verification_keys] # {:id,:key}
      # #<struct ApotonickApiTest::Table
      #   rows=[{:id=>1, :key=>"howmanycharactersdoweneed?"}]>

  # account_verification_key is set!
      assert verification_token = db[:account_verification_keys].rows[0][:key]
      assert_equal 43, verification_token.size

    end
  end
end
