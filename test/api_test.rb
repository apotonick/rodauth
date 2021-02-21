require "test_helper"

require "rodauth/features/base"
require "rodauth/features/email_base"
require "rodauth/features/create_account"
require "rodauth/features/verify_account"
require "rodauth/features/reset_password"
require "rodauth/features/login_password_requirements_base"
require "bcrypt"
      module Sequel
        CURRENT_TIMESTAMP = Class.new do
          def >(b)
            # raise b.inspect
            b
          end
        end.new
      end

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

        if options == :deadline # reset_password.rb:195
          return Deletable.new # the table with password-reset-keys is empty
        end

        column_name = options.keys.first
        value = options[column_name]

        set = rows.find_all { |row| row[column_name] == value }

        # return rows[0] if options[:id] == 1
        return self if set.empty?
        return Gettable.new(set, rows)
        # return []  # fixme: USE REAL SEQUEL

      end

      def empty?
        rows.empty?
      end

      def get(key)
        return nil if rows.empty?
        rows[0][key] # FIXME: eh
      end

      def update(options)
        # raise options.inspect
        rows[0].merge!(options)
      end

      class Deletable
        def delete
        end
      end

      class Gettable
        def initialize(set, rows)
          @set = set # TODO: this should be just one item
          @rows = rows # original set
        end

        def get(key)
          # raise key.inspect
          @set[0][key]
        end

        def delete
          @rows.delete(@set[0]) # yay to mutations!
        end

        def empty?
          @set.empty?
        end

        def update(options)
          @set[0].merge!(options)
        end

        def where(options)
          if options == :deadline # reset_password.rb:195
            return Deletable.new # the table with password-reset-keys is empty
          end
        end
      end
    end

    db = DB.new(
      {
        :users => Table.new([]),
        :account_verification_keys => Table.new([]),
        :account_password_reset_keys => Table.new([]),
      }
    )

      # def random_key
      #   Class.new do # FIXME: we don't want all methods from Base!
      #     include Rodauth::FEATURES[:base]
      #   end.new(1).send(:random_key)
      # end

      # def update_account(*args)
      #   Class.new do # FIXME: we don't want all methods from Base!
      #     include Rodauth::FEATURES[:base]
      #   end.new(1).send(:update_account, *args)
      # end

      # def account_from_key(*args, &block)
      #   base = Class.new do # FIXME: we don't want all methods from EmailBase!
      #     include Rodauth::FEATURES[:email_base]
      #     include Rodauth::FEATURES[:base] # we need {split_token}

      #     def db
      #       @__injected_db # FIXME: this sucks big time
      #     end
      #     def accounts_table;           :users; end
      #     def account_id_column;        :id; end

      #   end.new(nil)

      #   base.instance_variable_set(:@__injected_db, db)
      #   base.send(:account_from_key, *args, &block)
      # end

    MyRodauthApi = Class.new do
      def initialize(db)
        @db = db
      end

      attr_reader :db


      include Rodauth::FEATURES[:create_account]
      include Rodauth::FEATURES[:verify_account]
      include Rodauth::FEATURES[:login_password_requirements_base] # {#password_hash} and friends.
      include Rodauth::FEATURES[:reset_password]

      # FIXME: is it clever to include those two modules with all the baggage?
      include Rodauth::FEATURES[:base] # FIXME: currently used for {#random_key} and {#update_account}
      include Rodauth::FEATURES[:email_base]# {#account_from_key}

      def login_column; :email; end
      def accounts_table;           :users; end
      # def account_password_reset_keys_table;           :account_password_reset_keys; end
      # def verify_account_table;     :users; end
      def account_id_column;        :id; end
      def account_unverified_status_value; end # FIXME: this method is actually not "used" in Rodauth when {skip_status_checks?} but it's still called.
      def account_open_status_value; end # FIXME: this method is actually not "used" in Rodauth when {skip_status_checks?} but it's still called.
      def account_status_column;        :id; end
      def account_password_hash_column; :password_hashed; end
      attr_reader :account

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


      # needed in {verify_account.rb:195:in `new_account'}
      def account_from_login(*) # FIXME: this should be changed in Roda, this is called unnecessarily.
        @account
      end
      def account_id
        return unless @account
        @account.fetch(:id)
      end

      def set_deadline_value(*) # FIXME: this uses a lot of Sequel
      end

      def save_account(account:)
        @account = account # FIXME: mutable state on the instance, not good.
        super()
      end
      def verify_account(account:)
        @account = account # FIXME: mutable state on the instance, not good.
        #super() # DISCUSS: {#verify_account} sets a status that we don't want (do we?

        remove_verify_account_key
      end
      def reset_password_request(account:)
        @account = account # FIXME: mutable state on the instance, not good.

        generate_reset_password_key_value
        create_reset_password_key
      end

      def reset_password(account:, password:)
        @account = account # FIXME: mutable state on the instance, not good.

        set_password(password)
        remove_reset_password_key
      end

      def reset_verify_account_key # DISCUSS: should we add this to Rodauth itself? See https://twitter.com/jeremyevans0/status/1361346774703562758
        remove_verify_account_key
        generate_verify_account_key_value
        create_verify_account_key
      end

    end

    api = MyRodauthApi.new(db)




    # For {Create account} we need {:login}, {:password}, {:password_confirm}
    # UI does email check, also uniqueness
    #
    # TODO: use all in {password_requirements}

    # we skip all status checks from Rodauth because that's what our workflow does for us.
    # Luckily, Rodauth makes it simple to skip those

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
  # account CREATED
      password_hashed = db[:users].rows[0][:password_hashed]
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

  # RESET {verification_key}
  #   TODO: what about email?
      api.reset_verify_account_key

      assert new_verification_token = db[:account_verification_keys].rows[0][:key]
      assert_equal 43, new_verification_token.size
      assert verification_token != new_verification_token # there's a NEW, fresh {account_verification_key}

  # VERIFY account
      # trb NOTE: this happens in the PM {find_process_model}
      require "rack/utils" # FOR {timing_safe_eql?}
      api = MyRodauthApi.new(db)
      # puts "yuuuse WE CALL account_from_verify_account_key"
      account = api.account_from_verify_account_key("1_#{new_verification_token}") # FIXME: why do we need to prefix the user ID here?
      assert_equal "bla", account[0][:email]

      api = MyRodauthApi.new(db)
      api.verify_account(account: account[0])

      assert_equal [], db[:account_verification_keys].rows

  # request RESET PASSWORD
      api = MyRodauthApi.new(db)
      api.reset_password_request(account: account[0])

      assert password_reset_key = db[:account_password_reset_keys].rows[0][:key]
      assert_equal 1, db[:account_password_reset_keys].rows[0][:id]
  # RESET PASSWORD
      api = MyRodauthApi.new(db)
      account = api.account_from_reset_password_key("1_#{password_reset_key}")
      assert_equal "bla", account[0][:email]

      api = MyRodauthApi.new(db)
      api.reset_password(account: account[0], password: "new")

      assert_equal 60, db[:users].rows[0][:password_hashed].size
      assert db[:users].rows[0][:password_hashed] != password_hashed

      pp db[:users]
# TODO
# * set our {state} ourselves in the lib lane.
# * email sending could be a separate task?
# DISCUSS
# * do we need checks like {check_already_logged_in} or can the (lib) state machine prevent us from having to do this?
# * can we lock-in public Rodauth methods we use here? (@jeremy/@janko)
    end

  end
end
