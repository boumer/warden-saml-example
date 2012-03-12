#!/usr/bin/env ruby

require 'bundler/setup'
require 'sinatra'
require 'sinatra/flash'
require 'warden'
require 'ruby-saml'
require 'dm-core'
require 'dm-types'
require 'dm-validations'
require 'dm-timestamps'
require 'dm-migrations'
require 'bcrypt'

# User model
class User
  include DataMapper::Resource
  include BCrypt
  property :id,            Serial
  property :auth_method,   String, :default => "password"
  property :user_name,     String, :required => true
  property :mail_addr,     String, :required => true
  property :password_hash, String, :length => 60
  property :name_id,       String

  def password
    @password ||= Password.new(password_hash)
  end

  def password=(pass)
    @password = Password.create(pass)
    $stderr.puts @password
    self.password_hash = @password
  end

  def self.authenticate_with_password(user, pass)
    u = first(:user_name => user)
    if u.nil?
      nil
    else
      if u.password == pass
        u
      else
        nil
      end
    end
  end
end

# Initialize DM
DataMapper::Logger.new($stderr, :debug)
DataMapper.setup(:default, 'sqlite::memory:')
DataMapper.auto_migrate!

# Enable session
# use Rack::Session::Pool, :expire_after => 900
enable :sessions
# Configure warden
Warden::Strategies.add(:password) do
  def valid?
    params[:user] || params[:password]
  end

  def authenticate!
    u = User.authenticate_with_password(params[:user], params[:password])
    u.nil? ? fail!("Could not log in") : success!(u)
  end
end

use Warden::Manager do |manager|
  manager.default_strategies :basic
  manager.failure_app = self
end

# routes

get '/' do
  haml :index
end

get '/login' do
  env['warden'].authenticate!
end

get '/signup' do
  if env['warden'].authenticated?
    redirect '/'
  end
  haml :signup
end

# Create user account
post '/signup' do
  u = User.new
  u.user_name = params[:user][:user_name]
  u.mail_addr = params[:user][:mail_addr]
  u.password  = params[:user][:password]

  if u.save
    redirect '/'
  else
    errors = []
    u.errors.each do |e|
      errors << e
    end
    flash[:notice] = "Creating account is Failed: #{errors.join(',')}"
    redirect '/signup'
  end
end

get '/login/consume' do
end

get '/logout' do
end

get '/logout/response' do
end

